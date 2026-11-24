-- Durable, organization-aware approval and checkpoint storage for VulnFlow.
-- Apply with the Supabase CLI or paste into the Supabase SQL editor.

create extension if not exists pgcrypto;

create table if not exists public.vulnflow_organizations (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique check (slug = lower(slug)),
    display_name text,
    created_at timestamptz not null default now()
);

create table if not exists public.vulnflow_repositories (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.vulnflow_organizations(id) on delete cascade,
    repository_key text not null,
    display_name text,
    created_at timestamptz not null default now(),
    unique (organization_id, repository_key)
);

create table if not exists public.vulnflow_runs (
    id uuid primary key default gen_random_uuid(),
    repository_id uuid not null references public.vulnflow_repositories(id) on delete cascade,
    external_run_id text not null,
    status text not null default 'pending',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (repository_id, external_run_id)
);

create table if not exists public.vulnflow_plan_occurrences (
    id uuid primary key default gen_random_uuid(),
    repository_id uuid not null references public.vulnflow_repositories(id) on delete cascade,
    run_id uuid not null references public.vulnflow_runs(id) on delete cascade,
    external_plan_id text not null,
    approval_key text not null,
    context_hash text not null,
    plan_snapshot jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (repository_id, external_plan_id)
);

create table if not exists public.vulnflow_approval_requests (
    id uuid primary key default gen_random_uuid(),
    repository_id uuid not null references public.vulnflow_repositories(id) on delete cascade,
    approval_key text not null,
    context_hash text not null,
    status text not null default 'pending'
        check (status in ('pending', 'approved', 'rejected', 'expired', 'cancelled', 'superseded')),
    expires_at timestamptz,
    decided_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- This is the concurrency guard: two CI runs cannot create two active requests
-- for the same materially equivalent remediation in one repository.
create unique index if not exists vulnflow_one_pending_approval
    on public.vulnflow_approval_requests(repository_id, approval_key)
    where status = 'pending';

create index if not exists vulnflow_reusable_approval_lookup
    on public.vulnflow_approval_requests(repository_id, approval_key, created_at desc)
    where status in ('pending', 'approved', 'rejected');

create table if not exists public.vulnflow_approval_requirements (
    id uuid primary key default gen_random_uuid(),
    approval_request_id uuid not null references public.vulnflow_approval_requests(id) on delete cascade,
    approver_group text not null,
    quorum integer not null default 1 check (quorum > 0),
    step_order integer not null default 1 check (step_order > 0),
    created_at timestamptz not null default now(),
    unique (approval_request_id, approver_group)
);

create table if not exists public.vulnflow_approval_decisions (
    id uuid primary key default gen_random_uuid(),
    approval_request_id uuid not null references public.vulnflow_approval_requests(id) on delete cascade,
    reviewer text not null,
    reviewer_group text not null,
    approved boolean not null,
    reason text not null,
    created_at timestamptz not null default now()
);

create index if not exists vulnflow_decisions_by_request
    on public.vulnflow_approval_decisions(approval_request_id, reviewer_group, created_at desc);

create table if not exists public.vulnflow_plan_approval_links (
    plan_occurrence_id uuid primary key references public.vulnflow_plan_occurrences(id) on delete cascade,
    approval_request_id uuid not null references public.vulnflow_approval_requests(id) on delete cascade,
    created_at timestamptz not null default now()
);

create index if not exists vulnflow_links_by_request
    on public.vulnflow_plan_approval_links(approval_request_id);

create table if not exists public.vulnflow_workflow_checkpoints (
    id uuid primary key default gen_random_uuid(),
    run_id uuid not null unique references public.vulnflow_runs(id) on delete cascade,
    current_node text not null,
    status text not null,
    state jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

alter table public.vulnflow_organizations enable row level security;
alter table public.vulnflow_repositories enable row level security;
alter table public.vulnflow_runs enable row level security;
alter table public.vulnflow_plan_occurrences enable row level security;
alter table public.vulnflow_approval_requests enable row level security;
alter table public.vulnflow_approval_requirements enable row level security;
alter table public.vulnflow_approval_decisions enable row level security;
alter table public.vulnflow_plan_approval_links enable row level security;
alter table public.vulnflow_workflow_checkpoints enable row level security;

create or replace function public.vulnflow_claim_approval(
    p_organization_slug text,
    p_repository_key text,
    p_run_id text,
    p_plan_id text,
    p_approval_key text,
    p_context_hash text,
    p_plan_snapshot jsonb,
    p_checkpoint_status text default 'running',
    p_required_groups text[] default array['security']::text[]
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_org_id uuid;
    v_repo_id uuid;
    v_run_uuid uuid;
    v_plan_uuid uuid;
    v_request public.vulnflow_approval_requests%rowtype;
    v_group text;
    v_decision jsonb;
    v_created boolean := false;
begin
    if nullif(trim(p_organization_slug), '') is null
       or nullif(trim(p_repository_key), '') is null
       or nullif(trim(p_run_id), '') is null
       or nullif(trim(p_plan_id), '') is null
       or nullif(trim(p_approval_key), '') is null then
        raise exception 'organization, repository, run, plan, and approval key are required';
    end if;

    insert into public.vulnflow_organizations(slug, display_name)
    values (lower(trim(p_organization_slug)), trim(p_organization_slug))
    on conflict (slug) do update set display_name = coalesce(public.vulnflow_organizations.display_name, excluded.display_name)
    returning id into v_org_id;

    insert into public.vulnflow_repositories(organization_id, repository_key, display_name)
    values (v_org_id, lower(trim(p_repository_key)), trim(p_repository_key))
    on conflict (organization_id, repository_key) do update
        set display_name = coalesce(public.vulnflow_repositories.display_name, excluded.display_name)
    returning id into v_repo_id;

    insert into public.vulnflow_runs(repository_id, external_run_id, status)
    values (v_repo_id, p_run_id, coalesce(nullif(p_checkpoint_status, ''), 'running'))
    on conflict (repository_id, external_run_id) do update
        set status = excluded.status, updated_at = now()
    returning id into v_run_uuid;

    insert into public.vulnflow_plan_occurrences(
        repository_id, run_id, external_plan_id, approval_key, context_hash, plan_snapshot
    ) values (
        v_repo_id, v_run_uuid, p_plan_id, p_approval_key, p_context_hash, p_plan_snapshot
    )
    on conflict (repository_id, external_plan_id) do update set
        run_id = excluded.run_id,
        approval_key = excluded.approval_key,
        context_hash = excluded.context_hash,
        plan_snapshot = excluded.plan_snapshot,
        updated_at = now()
    returning id into v_plan_uuid;

    -- Serialize equivalent claims and expire stale pending requests before reuse.
    perform pg_advisory_xact_lock(hashtextextended(v_repo_id::text || ':' || p_approval_key, 0));
    update public.vulnflow_approval_requests
       set status = 'expired', updated_at = now()
     where repository_id = v_repo_id
       and approval_key = p_approval_key
       and status = 'pending'
       and expires_at is not null
       and expires_at <= now();

    select * into v_request
      from public.vulnflow_approval_requests
     where repository_id = v_repo_id
       and approval_key = p_approval_key
       and status in ('pending', 'approved', 'rejected')
       and (expires_at is null or expires_at > now())
     order by created_at desc
     limit 1;

    if v_request.id is null then
        v_created := true;
        insert into public.vulnflow_approval_requests(repository_id, approval_key, context_hash)
        values (v_repo_id, p_approval_key, p_context_hash)
        returning * into v_request;

        foreach v_group in array coalesce(p_required_groups, array['security']::text[])
        loop
            if nullif(trim(v_group), '') is not null then
                insert into public.vulnflow_approval_requirements(approval_request_id, approver_group)
                values (v_request.id, lower(trim(v_group)))
                on conflict do nothing;
            end if;
        end loop;
        if not exists (
            select 1 from public.vulnflow_approval_requirements where approval_request_id = v_request.id
        ) then
            insert into public.vulnflow_approval_requirements(approval_request_id, approver_group)
            values (v_request.id, 'security');
        end if;
    end if;

    insert into public.vulnflow_plan_approval_links(plan_occurrence_id, approval_request_id)
    values (v_plan_uuid, v_request.id)
    on conflict (plan_occurrence_id) do update set approval_request_id = excluded.approval_request_id;

    update public.vulnflow_runs
       set status = case when v_request.status = 'pending' then 'pending_approval' else status end,
           updated_at = now()
     where id = v_run_uuid;

    select jsonb_build_object(
        'approved', d.approved,
        'reviewer', d.reviewer,
        'reviewer_group', d.reviewer_group,
        'reason', d.reason,
        'timestamp', extract(epoch from d.created_at)
    ) into v_decision
      from public.vulnflow_approval_decisions d
     where d.approval_request_id = v_request.id
     order by d.created_at desc
     limit 1;

    return jsonb_build_object(
        'approval_request_id', v_request.id,
        'plan_id', p_plan_id,
        'approval_key', p_approval_key,
        'status', v_request.status,
        'reused', not v_created,
        'decision', v_decision
    );
end;
$$;

create or replace function public.vulnflow_get_plan_approval(
    p_organization_slug text,
    p_repository_key text,
    p_plan_id text
) returns jsonb
language sql
stable
security definer
set search_path = public, pg_temp
as $$
    select coalesce((
        select jsonb_build_object(
            'approval_request_id', ar.id,
            'plan_id', po.external_plan_id,
            'run_id', runs.external_run_id,
            'approval_key', ar.approval_key,
            'status', ar.status,
            'decision', (
                select jsonb_build_object(
                    'approved', d.approved,
                    'reviewer', d.reviewer,
                    'reviewer_group', d.reviewer_group,
                    'reason', d.reason,
                    'timestamp', extract(epoch from d.created_at)
                )
                from public.vulnflow_approval_decisions d
                where d.approval_request_id = ar.id
                order by d.created_at desc
                limit 1
            )
        )
        from public.vulnflow_organizations o
        join public.vulnflow_repositories r on r.organization_id = o.id
        join public.vulnflow_plan_occurrences po on po.repository_id = r.id
        join public.vulnflow_runs runs on runs.id = po.run_id
        join public.vulnflow_plan_approval_links pal on pal.plan_occurrence_id = po.id
        join public.vulnflow_approval_requests ar on ar.id = pal.approval_request_id
        where o.slug = lower(trim(p_organization_slug))
          and r.repository_key = lower(trim(p_repository_key))
          and po.external_plan_id = p_plan_id
        order by ar.created_at desc
        limit 1
    ), '{}'::jsonb);
$$;

create or replace function public.vulnflow_record_approval_decision(
    p_organization_slug text,
    p_repository_key text,
    p_plan_id text,
    p_approved boolean,
    p_reviewer text,
    p_reviewer_group text,
    p_reason text
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_repo_id uuid;
    v_request_id uuid;
    v_request_ids uuid[];
    v_status text;
    v_pending_count integer := 0;
    v_approved_count integer := 0;
    v_rejected_count integer := 0;
    v_resume_run_id text;
begin
    if nullif(trim(p_reviewer), '') is null or nullif(trim(p_reviewer_group), '') is null then
        raise exception 'reviewer and reviewer_group are required';
    end if;

    select r.id into v_repo_id
      from public.vulnflow_organizations o
      join public.vulnflow_repositories r on r.organization_id = o.id
     where o.slug = lower(trim(p_organization_slug))
       and r.repository_key = lower(trim(p_repository_key));
    if v_repo_id is null then
        raise exception 'repository is not registered';
    end if;

    if lower(p_plan_id) in ('all', '*') then
        select array_agg(id order by created_at) into v_request_ids
          from public.vulnflow_approval_requests
         where repository_id = v_repo_id and status = 'pending';
    else
        select array_agg(request_id) into v_request_ids from (
            select ar.id as request_id
              from public.vulnflow_plan_occurrences po
              join public.vulnflow_plan_approval_links pal on pal.plan_occurrence_id = po.id
              join public.vulnflow_approval_requests ar on ar.id = pal.approval_request_id
             where po.repository_id = v_repo_id
               and po.external_plan_id = p_plan_id
               and ar.status not in ('expired', 'cancelled', 'superseded')
             order by ar.created_at desc
             limit 1
        ) target;
    end if;

    if coalesce(cardinality(v_request_ids), 0) = 0 then
        raise exception 'no active approval request found for plan %', p_plan_id;
    end if;

    foreach v_request_id in array v_request_ids
    loop
        perform pg_advisory_xact_lock(hashtextextended(v_request_id::text, 0));
        if not exists (
            select 1 from public.vulnflow_approval_requirements
             where approval_request_id = v_request_id
               and approver_group = lower(trim(p_reviewer_group))
        ) then
            raise exception 'group % is not required for this approval', p_reviewer_group;
        end if;

        insert into public.vulnflow_approval_decisions(
            approval_request_id, reviewer, reviewer_group, approved, reason
        ) values (
            v_request_id,
            trim(p_reviewer),
            lower(trim(p_reviewer_group)),
            p_approved,
            coalesce(nullif(trim(p_reason), ''), case when p_approved then 'Approved' else 'Rejected' end)
        );

        with latest_by_reviewer as (
            select distinct on (reviewer, reviewer_group)
                   reviewer, reviewer_group, approved
              from public.vulnflow_approval_decisions
             where approval_request_id = v_request_id
             order by reviewer, reviewer_group, created_at desc
        ), requirement_state as (
            select req.id,
                   req.quorum,
                   count(*) filter (where latest.approved) as approvals,
                   count(*) filter (where not latest.approved) as rejections
              from public.vulnflow_approval_requirements req
              left join latest_by_reviewer latest on latest.reviewer_group = req.approver_group
             where req.approval_request_id = v_request_id
             group by req.id, req.quorum
        )
        select case
            when coalesce(sum(rejections), 0) > 0 then 'rejected'
            when bool_and(approvals >= quorum) then 'approved'
            else 'pending'
        end into v_status
        from requirement_state;

        update public.vulnflow_approval_requests
           set status = v_status,
               decided_at = case when v_status in ('approved', 'rejected') then now() else null end,
               updated_at = now()
         where id = v_request_id;

        if v_status = 'approved' then
            v_approved_count := v_approved_count + 1;
        elsif v_status = 'rejected' then
            v_rejected_count := v_rejected_count + 1;
        else
            v_pending_count := v_pending_count + 1;
        end if;
    end loop;

    if v_pending_count > 0 then
        v_status := 'pending';
    elsif v_rejected_count > 0 then
        v_status := 'rejected';
    else
        v_status := 'approved';
    end if;

    select runs.external_run_id into v_resume_run_id
      from public.vulnflow_plan_approval_links links
      join public.vulnflow_plan_occurrences plans on plans.id = links.plan_occurrence_id
      join public.vulnflow_runs runs on runs.id = plans.run_id
     where links.approval_request_id = any(v_request_ids)
     order by plans.updated_at desc
     limit 1;

    return jsonb_build_object(
        'plan_id', p_plan_id,
        'run_id', v_resume_run_id,
        'status', v_status,
        'approved_count', v_approved_count,
        'pending_count', v_pending_count,
        'rejected_count', v_rejected_count,
        'decision', jsonb_build_object(
            'approved', p_approved,
            'reviewer', trim(p_reviewer),
            'reviewer_group', lower(trim(p_reviewer_group)),
            'reason', p_reason,
            'timestamp', extract(epoch from now())
        )
    );
end;
$$;

create or replace function public.vulnflow_save_checkpoint(
    p_organization_slug text,
    p_repository_key text,
    p_run_id text,
    p_status text,
    p_current_node text,
    p_state jsonb
) returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_org_id uuid;
    v_repo_id uuid;
    v_run_uuid uuid;
begin
    insert into public.vulnflow_organizations(slug, display_name)
    values (lower(trim(p_organization_slug)), trim(p_organization_slug))
    on conflict (slug) do update set display_name = coalesce(public.vulnflow_organizations.display_name, excluded.display_name)
    returning id into v_org_id;

    insert into public.vulnflow_repositories(organization_id, repository_key, display_name)
    values (v_org_id, lower(trim(p_repository_key)), trim(p_repository_key))
    on conflict (organization_id, repository_key) do update
        set display_name = coalesce(public.vulnflow_repositories.display_name, excluded.display_name)
    returning id into v_repo_id;

    insert into public.vulnflow_runs(repository_id, external_run_id, status)
    values (v_repo_id, p_run_id, p_status)
    on conflict (repository_id, external_run_id) do update
        set status = excluded.status, updated_at = now()
    returning id into v_run_uuid;

    insert into public.vulnflow_workflow_checkpoints(run_id, current_node, status, state)
    values (v_run_uuid, p_current_node, p_status, p_state)
    on conflict (run_id) do update set
        current_node = excluded.current_node,
        status = excluded.status,
        state = excluded.state,
        updated_at = now();
end;
$$;

create or replace function public.vulnflow_load_checkpoint(
    p_organization_slug text,
    p_repository_key text,
    p_run_id text default null
) returns jsonb
language sql
stable
security definer
set search_path = public, pg_temp
as $$
    select coalesce((
        select jsonb_build_object(
            'run_id', runs.external_run_id,
            'status', cp.status,
            'current_node', cp.current_node,
            'state', cp.state,
            'updated_at', cp.updated_at
        )
          from public.vulnflow_organizations o
          join public.vulnflow_repositories repos on repos.organization_id = o.id
          join public.vulnflow_runs runs on runs.repository_id = repos.id
          join public.vulnflow_workflow_checkpoints cp on cp.run_id = runs.id
         where o.slug = lower(trim(p_organization_slug))
           and repos.repository_key = lower(trim(p_repository_key))
           and (p_run_id is null or runs.external_run_id = p_run_id)
         order by cp.updated_at desc
         limit 1
    ), '{}'::jsonb);
$$;

create or replace view public.vulnflow_pending_approvals
with (security_invoker = true)
as
select
    o.slug as organization_slug,
    repos.repository_key,
    ar.id as approval_request_id,
    ar.approval_key,
    po.external_plan_id as plan_id,
    po.plan_snapshot ->> 'target_package' as target_package,
    po.plan_snapshot ->> 'root_cause_id' as root_cause_id,
    po.plan_snapshot ->> 'target_version' as target_version,
    po.plan_snapshot ->> 'action' as action,
    po.plan_snapshot ->> 'risk_tier' as risk_tier,
    po.plan_snapshot #>> '{policy_result,reason}' as policy_reason,
    po.plan_snapshot ->> 'rationale' as rationale,
    po.plan_snapshot #>> '{evidence,0,diff}' as diff,
    coalesce(req.required_groups, array[]::text[]) as required_groups,
    coalesce(sat.satisfied_groups, array[]::text[]) as satisfied_groups,
    ar.created_at
from public.vulnflow_approval_requests ar
join public.vulnflow_repositories repos on repos.id = ar.repository_id
join public.vulnflow_organizations o on o.id = repos.organization_id
join lateral (
    select occurrence.external_plan_id, occurrence.plan_snapshot
      from public.vulnflow_plan_approval_links link
      join public.vulnflow_plan_occurrences occurrence on occurrence.id = link.plan_occurrence_id
     where link.approval_request_id = ar.id
     order by occurrence.created_at desc
     limit 1
) po on true
left join lateral (
    select array_agg(approver_group order by step_order) as required_groups
      from public.vulnflow_approval_requirements
     where approval_request_id = ar.id
) req on true
left join lateral (
    with latest as (
        select distinct on (reviewer, reviewer_group) reviewer_group, approved
          from public.vulnflow_approval_decisions
         where approval_request_id = ar.id
         order by reviewer, reviewer_group, created_at desc
    )
    select array_agg(distinct reviewer_group) filter (where approved) as satisfied_groups from latest
) sat on true
where ar.status = 'pending';

grant usage on schema public to service_role;
grant all on table public.vulnflow_organizations to service_role;
grant all on table public.vulnflow_repositories to service_role;
grant all on table public.vulnflow_runs to service_role;
grant all on table public.vulnflow_plan_occurrences to service_role;
grant all on table public.vulnflow_approval_requests to service_role;
grant all on table public.vulnflow_approval_requirements to service_role;
grant all on table public.vulnflow_approval_decisions to service_role;
grant all on table public.vulnflow_plan_approval_links to service_role;
grant all on table public.vulnflow_workflow_checkpoints to service_role;
grant select on public.vulnflow_pending_approvals to service_role;

revoke all on function public.vulnflow_claim_approval(text, text, text, text, text, text, jsonb, text, text[]) from public, anon, authenticated;
revoke all on function public.vulnflow_get_plan_approval(text, text, text) from public, anon, authenticated;
revoke all on function public.vulnflow_record_approval_decision(text, text, text, boolean, text, text, text) from public, anon, authenticated;
revoke all on function public.vulnflow_save_checkpoint(text, text, text, text, text, jsonb) from public, anon, authenticated;
revoke all on function public.vulnflow_load_checkpoint(text, text, text) from public, anon, authenticated;

grant execute on function public.vulnflow_claim_approval(text, text, text, text, text, text, jsonb, text, text[]) to service_role;
grant execute on function public.vulnflow_get_plan_approval(text, text, text) to service_role;
grant execute on function public.vulnflow_record_approval_decision(text, text, text, boolean, text, text, text) to service_role;
grant execute on function public.vulnflow_save_checkpoint(text, text, text, text, text, jsonb) to service_role;
grant execute on function public.vulnflow_load_checkpoint(text, text, text) to service_role;
