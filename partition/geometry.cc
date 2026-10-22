// Immutable, spherical point-in-MultiPolygon lookup using the same S2 geometry
// family as MongoDB's 2dsphere engine. Parsed/indexed once during nginx config.
#include "geometry.h"
#include <json-c/json.h>
#include <s2/s2latlng.h>
#include <s2/s2loop.h>
#include <s2/s2polygon.h>
#include <s2/s2error.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
struct Partition {
    std::string key;
    int specificity;
    std::vector<std::unique_ptr<S2Polygon>> shapes;
};
using Cache = std::vector<Partition>;
json_object *field(json_object *object, const char *name) {
    json_object *value = nullptr;
    json_object_object_get_ex(object, name, &value);
    return value;
}
size_t count(json_object *array) {
    if (!array || !json_object_is_type(array, json_type_array))
        throw std::runtime_error("expected coordinate array");
    return json_object_array_length(array);
}
json_object *at(json_object *array, size_t index) {
    return json_object_array_get_idx(array, index);
}
S2Point point(json_object *coordinate) {
    if (count(coordinate) != 2) throw std::runtime_error("expected coordinate pair");
    for (size_t i=0; i<2; ++i) {
        if (!json_object_is_type(at(coordinate,i), json_type_double) &&
            !json_object_is_type(at(coordinate,i), json_type_int))
            throw std::runtime_error("expected numeric coordinate");
    }
    double longitude=json_object_get_double(at(coordinate,0));
    double latitude=json_object_get_double(at(coordinate,1));
    if (!std::isfinite(latitude) || !std::isfinite(longitude) ||
        std::abs(latitude)>90 || std::abs(longitude)>180)
        throw std::runtime_error("coordinate out of range");
    return S2LatLng::FromDegrees(latitude,longitude).ToPoint();
}
std::unique_ptr<S2Polygon> polygon(json_object *rings) {
    if (!count(rings)) throw std::runtime_error("empty polygon");
    std::vector<std::unique_ptr<S2Loop>> loops;
    for (size_t j=0;j<count(rings);++j) {
        auto ring=at(rings,j);
        size_t size=count(ring);
        if (size<4 || point(at(ring,0))!=point(at(ring,size-1)))
            throw std::runtime_error("unclosed or short ring");
        std::vector<S2Point> points;
        points.reserve(size-1);
        for (size_t k=0;k<size-1;++k) {
            S2Point vertex=point(at(ring,k));
            if (points.empty() || points.back()!=vertex) points.push_back(vertex);
        }
        auto loop=std::make_unique<S2Loop>(points);
        S2Error error;
        if (loop->FindValidationError(&error)) throw std::runtime_error("invalid spherical ring");
        loop->Normalize();
        loops.push_back(std::move(loop));
    }
    auto shape=std::make_unique<S2Polygon>();
    shape->InitNested(std::move(loops));
    S2Error error;
    if (shape->FindValidationError(&error)) throw std::runtime_error("invalid spherical polygon");
    // Finish lazy indexing before worker fork / the first request.
    shape->Contains(S2LatLng::FromDegrees(0,0).ToPoint());
    return shape;
}
}

extern "C" void *msc_geometry_load(const char *path, char *error, size_t error_size) {
    try {
        using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
        Json rows(json_object_from_file(path), &json_object_put);
        if (!rows || count(rows.get())>10000) throw std::runtime_error("invalid partition snapshot");
        auto cache=std::make_unique<Cache>();
        for (size_t i=0;i<count(rows.get());++i) {
            auto row=at(rows.get(),i);
            auto key=field(row,"partitionKey"); auto geometry=field(row,"geometry");
            if (!key || !geometry) continue;
            if (!json_object_is_type(key,json_type_string)) throw std::runtime_error("invalid partition key");
            std::string name=json_object_get_string(key);
            if (name.empty()) continue;
            if (name.size()>1024 || std::any_of(cache->begin(),cache->end(),[&](const Partition &p){return p.key==name;}))
                throw std::runtime_error("duplicate or oversized partition key");
            Partition partition{name,json_object_get_int(field(row,"specificity")),{}};
            auto type=field(geometry,"type"); auto coordinates=field(geometry,"coordinates");
            if (!type) throw std::runtime_error("missing geometry type");
            std::string kind=json_object_get_string(type);
            if (kind=="Polygon") partition.shapes.push_back(polygon(coordinates));
            else if (kind=="MultiPolygon") {
                if (!count(coordinates)) throw std::runtime_error("empty multipolygon");
                for (size_t j=0;j<count(coordinates);++j) partition.shapes.push_back(polygon(at(coordinates,j)));
            } else throw std::runtime_error("unsupported geometry type");
            cache->push_back(std::move(partition));
        }
        std::stable_sort(cache->begin(),cache->end(),[](const Partition &a,const Partition &b){return a.specificity>b.specificity;});
        return cache.release();
    } catch (const std::exception &exception) {
        std::snprintf(error,error_size,"%s",exception.what());
        return nullptr;
    }
}
extern "C" const char *msc_geometry_find(void *opaque, double latitude, double longitude) {
    auto cache=static_cast<Cache *>(opaque);
    S2Point query=S2LatLng::FromDegrees(latitude,longitude).ToPoint();
    for (const auto &partition:*cache)
        for (const auto &shape:partition.shapes)
            if (shape->Contains(query)) return partition.key.c_str();
    return nullptr;
}
extern "C" void msc_geometry_free(void *cache) { delete static_cast<Cache *>(cache); }
