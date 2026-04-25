-- Create user_identities table
CREATE TABLE IF NOT EXISTS user_identities (
    sub_id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    phone_number VARCHAR(255) NOT NULL,
    authentication_method VARCHAR(50) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_identities_email ON user_identities(email);
CREATE INDEX IF NOT EXISTS idx_user_identities_phone_number ON user_identities(phone_number);
