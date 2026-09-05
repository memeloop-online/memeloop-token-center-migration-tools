CREATE TABLE IF NOT EXISTS model_price_tiers (
    id TEXT PRIMARY KEY,
    model TEXT NOT NULL,
    currency TEXT NOT NULL,
    service_tier TEXT NOT NULL,
    input_micros_per_million BIGINT NOT NULL,
    cached_input_micros_per_million BIGINT NOT NULL,
    cache_write_micros_per_million BIGINT NOT NULL,
    output_micros_per_million BIGINT NOT NULL,
    cache_price_estimated BIGINT NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(model, currency, service_tier)
);

INSERT INTO model_price_tiers (
    id, model, currency, service_tier,
    input_micros_per_million, cached_input_micros_per_million,
    cache_write_micros_per_million, output_micros_per_million,
    source, updated_at, cache_price_estimated
)
SELECT id, model, currency, 'default',
       input_micros_per_million, input_micros_per_million,
       input_micros_per_million, output_micros_per_million,
       source, updated_at, 1
FROM model_prices
WHERE 1 = 1
ON CONFLICT(model, currency, service_tier) DO NOTHING;

ALTER TABLE usage_reservations ADD COLUMN price_snapshot_json TEXT;

CREATE INDEX IF NOT EXISTS idx_model_price_tiers_currency_model
    ON model_price_tiers(currency, model, service_tier);
