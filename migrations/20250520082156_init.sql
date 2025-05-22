-- +goose Up
-- +goose StatementBegin
CREATE TABLE sessions(
    id uuid PRIMARY KEY , 
    user_id uuid NOT NULL, 
    refresh_token bytea NOT NULL, 
    user_agent text NOT NULL, 
    ip_address inet NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE sessions;
-- +goose StatementEnd
