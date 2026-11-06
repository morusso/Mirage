# GeoLite2 databases

Not committed (MaxMind licence). Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
with a free MaxMind account, put them in this directory, then in `deploy/.env` set:

    MIRAGE_GEOIP_CITY_DB=/geoip/GeoLite2-City.mmdb
    MIRAGE_GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb

The directory is mounted read-only into the enrichment worker. Without the files the
worker still runs and leaves country, city and ASN empty.
