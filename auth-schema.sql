-- sqlite3 auth.db < auth-schema.sql

drop table if exists ApiClient;
create table ApiClient (
  id integer primary key autoincrement,
  public_key  text not null,
  secret_key text not null
);

INSERT INTO ApiClient (id, public_key, secret_key) VALUES (1, 'mobile_app', '$secret$');
INSERT INTO ApiClient (id, public_key, secret_key) VALUES (2, 'smartwatch', '$secret$');
