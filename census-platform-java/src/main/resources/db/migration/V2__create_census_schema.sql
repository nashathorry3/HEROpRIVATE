-- ============================================================
-- V2: Census (Demographic) Database Schema
-- Anonymized — NO identity information whatsoever
-- ============================================================

CREATE SCHEMA IF NOT EXISTS census;

-- ─── Reference Tables ────────────────────────────────────────

CREATE TABLE census.regions (
    code            VARCHAR(10) PRIMARY KEY,
    name_local      VARCHAR(100) NOT NULL,
    name_en         VARCHAR(100) NOT NULL,
    parent_code     VARCHAR(10) REFERENCES census.regions(code),
    level           SMALLINT NOT NULL,  -- 1=country, 2=province, 3=district
    population_min  INTEGER,            -- k-anonymity enforcement
    is_active       BOOLEAN DEFAULT TRUE,
    CONSTRAINT valid_level CHECK (level BETWEEN 1 AND 3)
);

CREATE TABLE census.ethnicities (
    code        VARCHAR(20) PRIMARY KEY,
    name_local  VARCHAR(100) NOT NULL,
    name_en     VARCHAR(100) NOT NULL,
    is_active   BOOLEAN DEFAULT TRUE
);

CREATE TABLE census.languages (
    code        VARCHAR(20) PRIMARY KEY,  -- ISO 639-3
    name_local  VARCHAR(100) NOT NULL,
    name_en     VARCHAR(100) NOT NULL,
    script      VARCHAR(20)
);

CREATE TABLE census.religions (
    code        VARCHAR(20) PRIMARY KEY,
    name_local  VARCHAR(100) NOT NULL,
    name_en     VARCHAR(100) NOT NULL,
    category    VARCHAR(50)
);

-- ─── Census Responses ─────────────────────────────────────────

CREATE TABLE census.census_responses (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_nullifier         BYTEA NOT NULL UNIQUE,  -- Prevents double-submission

    -- Geographic (district level max — no street address ever)
    region_code             VARCHAR(10) NOT NULL REFERENCES census.regions(code),
    district_code           VARCHAR(10),
    is_urban                BOOLEAN,

    -- Demographic (self-reported, all voluntary)
    ethnicity_code          VARCHAR(20) REFERENCES census.ethnicities(code),
    language_code           VARCHAR(20) REFERENCES census.languages(code),
    religion_code           VARCHAR(20) REFERENCES census.religions(code),
    age_bracket             VARCHAR(10),
    gender_code             VARCHAR(10),
    household_size          SMALLINT,

    -- Socioeconomic
    education_level         VARCHAR(20),
    employment_status       VARCHAR(20),
    housing_type            VARCHAR(20),

    -- Submission metadata (no IP, no device)
    submission_channel      VARCHAR(20),
    completion_rate         NUMERIC(3,2),
    response_time_seconds   INTEGER,
    submitted_at            TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT valid_age_bracket CHECK (
        age_bracket IS NULL OR age_bracket IN (
            'under-18','18-24','25-34','35-44','45-54','55-64','65+'
        )
    ),
    CONSTRAINT valid_household_size CHECK (
        household_size IS NULL OR household_size BETWEEN 1 AND 30
    ),
    CONSTRAINT valid_completion_rate CHECK (
        completion_rate IS NULL OR completion_rate BETWEEN 0.0 AND 1.0
    )
);

CREATE INDEX idx_census_region     ON census.census_responses (region_code);
CREATE INDEX idx_census_submitted  ON census.census_responses (submitted_at);
CREATE INDEX idx_census_ethnicity  ON census.census_responses (ethnicity_code);

-- ─── Seed Reference Data ──────────────────────────────────────

INSERT INTO census.regions (code, name_local, name_en, level) VALUES
    ('IQ',  'العراق',           'Iraq',             1),
    ('BG',  'بغداد',            'Baghdad',           2),
    ('BS',  'البصرة',           'Basra',             2),
    ('MO',  'الموصل / نينوى',   'Mosul / Nineveh',   2),
    ('ER',  'أربيل',            'Erbil',             2),
    ('SL',  'السليمانية',       'Sulaymaniyah',      2),
    ('KR',  'كركوك',            'Kirkuk',            2),
    ('AN',  'الأنبار',          'Anbar',             2),
    ('DY',  'ديالى',            'Diyala',            2),
    ('BB',  'بابل',             'Babylon',           2),
    ('KR2', 'كربلاء',           'Karbala',           2),
    ('NJ',  'النجف',            'Najaf',             2),
    ('DH',  'دهوك',             'Duhok',             2),
    ('HF',  'حلبجة',            'Halabja',           2),
    ('MY',  'ميسان',            'Maysan',            2),
    ('MT',  'المثنى',           'Muthanna',          2),
    ('QD',  'القادسية',         'Al-Qadisiyyah',     2),
    ('SK',  'صلاح الدين',       'Salah ad-Din',      2),
    ('TK',  'التأميم',          'Thi-Qar',           2),
    ('WS',  'واسط',             'Wasit',             2);

INSERT INTO census.ethnicities (code, name_local, name_en) VALUES
    ('arab',      'عربي',       'Arab'),
    ('kurd',      'كردي',       'Kurdish'),
    ('turkmen',   'تركماني',    'Turkmen'),
    ('syriac',    'سرياني',     'Syriac/Assyrian'),
    ('armenian',  'أرمني',      'Armenian'),
    ('shabak',    'شبكي',       'Shabaki'),
    ('yazidi',    'إيزيدي',     'Yazidi'),
    ('other',     'أخرى',       'Other'),
    ('prefer_not','أفضل عدم الإفصاح', 'Prefer not to say');

INSERT INTO census.languages (code, name_local, name_en, script) VALUES
    ('ara', 'العربية',         'Arabic',           'arabic'),
    ('ckb', 'كردي سوراني',    'Kurdish (Sorani)',  'arabic'),
    ('kmr', 'كردي كرمانجي',   'Kurdish (Kurmanji)','latin'),
    ('tuk', 'التركمانية',      'Turkmen',           'latin'),
    ('syr', 'السريانية',       'Syriac',            'syriac'),
    ('hye', 'الأرمنية',       'Armenian',          'armenian'),
    ('eng', 'الإنجليزية',      'English',           'latin');

INSERT INTO census.religions (code, name_local, name_en, category) VALUES
    ('islam_sunni',  'إسلام سني',         'Islam (Sunni)',    'Islam'),
    ('islam_shia',   'إسلام شيعي',        'Islam (Shia)',     'Islam'),
    ('islam_other',  'إسلام - أخرى',      'Islam (Other)',    'Islam'),
    ('christianity', 'مسيحية',            'Christianity',     'Christianity'),
    ('yazidi',       'إيزيدية',           'Yazidi',           'Yazidi'),
    ('mandaean',     'مندائية',           'Mandaean',         'Mandaean'),
    ('kakai',        'كاكائية',           'Kakai',            'Other'),
    ('other',        'أخرى',              'Other',            'Other'),
    ('prefer_not',   'أفضل عدم الإفصاح', 'Prefer not to say', NULL);
