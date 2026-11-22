-- Electro Quiz · base de datos (Supabase / PostgreSQL)
-- Pegá TODO este archivo en Supabase > SQL Editor > Run. Se puede ejecutar más de una vez sin romper nada.

create table if not exists users (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  name_key    text not null unique,          -- nombre en minúsculas, para que "Juan" y "juan" sean el mismo
  created_at  timestamptz not null default now()
);

create table if not exists credentials (       -- la "huella": una llave pública por dispositivo
  id          text primary key,              -- id de la credencial (base64url)
  user_id     uuid not null references users(id) on delete cascade,
  public_key  jsonb not null,
  alg         int  not null,
  counter     bigint not null default 0,
  created_at  timestamptz not null default now()
);
create index if not exists credentials_user_idx on credentials(user_id);

create table if not exists codes (             -- códigos de activación de UN SOLO USO
  code_hash   text primary key,              -- se guarda el hash, nunca el código
  label       text,                          -- "para Juan Pérez" (solo para vos)
  for_user    uuid references users(id) on delete cascade,  -- si es un código de reinicio de una cuenta existente
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default now() + interval '14 days',
  used_at     timestamptz,
  used_by     uuid
);

create table if not exists sessions (
  token_hash  text primary key,
  user_id     uuid not null references users(id) on delete cascade,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null
);
create index if not exists sessions_user_idx on sessions(user_id);

create table if not exists progress (
  user_id     uuid primary key references users(id) on delete cascade,
  data        jsonb not null,
  updated_at  timestamptz not null default now()
);

create table if not exists challenges (        -- desafíos temporales del registro / ingreso
  id          uuid primary key default gen_random_uuid(),
  kind        text not null,
  challenge   text not null,
  payload     jsonb not null default '{}'::jsonb,
  expires_at  timestamptz not null default now() + interval '5 minutes'
);

-- Seguridad: nadie puede leer ni escribir estas tablas desde internet.
-- Solo la función "api" (que usa la conexión interna del proyecto) accede a los datos.
alter table users       enable row level security;
alter table credentials enable row level security;
alter table codes       enable row level security;
alter table sessions    enable row level security;
alter table progress    enable row level security;
alter table challenges  enable row level security;
