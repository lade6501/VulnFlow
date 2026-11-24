-- Cached graph/RAG batch enrichment keyed by deterministic plan context.

create table if not exists public.vulnflow_enrichment_cache (
    id uuid primary key default gen_random_uuid(),
    repository_id uuid not null references public.vulnflow_repositories(id) on delete cascade,
    cache_key text not null,
    schema_version integer not null default 1,
    enrichment jsonb not null,
    context_summary jsonb not null default '{}'::jsonb,
    provider text,
    model text,
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (repository_id, cache_key)
);

alter table public.vulnflow_enrichment_cache enable row level security;

create or replace function public.vulnflow_get_enrichment_cache(
    p_organization_slug text,
    p_repository_key text,
    p_cache_keys text[]
) returns jsonb
language sql
stable
security definer
set search_path = public, pg_temp
as $$
    select coalesce(jsonb_agg(jsonb_build_object(
        'cache_key', cache.cache_key,
        'schema_version', cache.schema_version,
        'enrichment', cache.enrichment,
        'provider', cache.provider,
        'model', cache.model,
        'updated_at', cache.updated_at
    )), '[]'::jsonb)
    from public.vulnflow_organizations org
    join public.vulnflow_repositories repo on repo.organization_id = org.id
    join public.vulnflow_enrichment_cache cache on cache.repository_id = repo.id
    where org.slug = lower(trim(p_organization_slug))
      and repo.repository_key = lower(trim(p_repository_key))
      and cache.cache_key = any(coalesce(p_cache_keys, array[]::text[]))
      and (cache.expires_at is null or cache.expires_at > now());
$$;

create or replace function public.vulnflow_save_enrichment_cache(
    p_organization_slug text,
    p_repository_key text,
    p_entries jsonb
) returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_org_id uuid;
    v_repo_id uuid;
    v_entry jsonb;
begin
    if jsonb_typeof(p_entries) <> 'array' then
        raise exception 'p_entries must be a JSON array';
    end if;

    insert into public.vulnflow_organizations(slug, display_name)
    values (lower(trim(p_organization_slug)), trim(p_organization_slug))
    on conflict (slug) do update
        set display_name = coalesce(public.vulnflow_organizations.display_name, excluded.display_name)
    returning id into v_org_id;

    insert into public.vulnflow_repositories(organization_id, repository_key, display_name)
    values (v_org_id, lower(trim(p_repository_key)), trim(p_repository_key))
    on conflict (organization_id, repository_key) do update
        set display_name = coalesce(public.vulnflow_repositories.display_name, excluded.display_name)
    returning id into v_repo_id;

    for v_entry in select value from jsonb_array_elements(p_entries)
    loop
        if nullif(v_entry ->> 'cache_key', '') is null
           or jsonb_typeof(v_entry -> 'enrichment') <> 'object' then
            raise exception 'each cache entry requires cache_key and enrichment object';
        end if;

        insert into public.vulnflow_enrichment_cache(
            repository_id,
            cache_key,
            schema_version,
            enrichment,
            context_summary,
            provider,
            model,
            expires_at
        ) values (
            v_repo_id,
            v_entry ->> 'cache_key',
            coalesce((v_entry ->> 'schema_version')::integer, 1),
            v_entry -> 'enrichment',
            coalesce(v_entry -> 'context_summary', '{}'::jsonb),
            v_entry ->> 'provider',
            v_entry ->> 'model',
            nullif(v_entry ->> 'expires_at', '')::timestamptz
        )
        on conflict (repository_id, cache_key) do update set
            schema_version = excluded.schema_version,
            enrichment = excluded.enrichment,
            context_summary = excluded.context_summary,
            provider = excluded.provider,
            model = excluded.model,
            expires_at = excluded.expires_at,
            updated_at = now();
    end loop;
end;
$$;

grant all on table public.vulnflow_enrichment_cache to service_role;

revoke all on function public.vulnflow_get_enrichment_cache(text, text, text[]) from public, anon, authenticated;
revoke all on function public.vulnflow_save_enrichment_cache(text, text, jsonb) from public, anon, authenticated;

grant execute on function public.vulnflow_get_enrichment_cache(text, text, text[]) to service_role;
grant execute on function public.vulnflow_save_enrichment_cache(text, text, jsonb) to service_role;
