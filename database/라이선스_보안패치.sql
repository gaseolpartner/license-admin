-- =====================================================================
--  라이선스 보안 패치 (노무대장 · 수량산출)  — 2026-11-04
--  문제: 프로그램 안에 들어 있는 공개 키(anon)만으로
--        · nomu_licenses 전체 조회(업체·이름·이메일·전화)와 수정(만료일 연장)이 가능했음
--        · suryang_licenses 는 모든 작업이 가능했음
--        · 라이선스 생성(generate_*)·PC 해제(reset_*_machine)도 누구나 부를 수 있었음
--  해결:
--    1) verify_*_license 는 본문 그대로, SECURITY DEFINER 로만 바꿈 → 고객 프로그램 인증은 지금처럼 동작
--    2) 공개(public) 조회·수정 규칙 삭제, 비교견적 슈퍼관리자(gp_is_superadmin)만 관리
--    3) generate_* / reset_*_machine 은 로그인한 사람만 부를 수 있고, 표 규칙상 슈퍼관리자만 실제로 됨
-- =====================================================================
begin;

-- 1) 인증 함수: 함수 스스로 표를 읽고 쓰게 (본문 변경 없음)
alter function public.verify_nomu_license(character varying, character varying, jsonb) security definer;
alter function public.verify_nomu_license(character varying, character varying, jsonb) set search_path = public;
do $$ declare f text; begin
  -- 수량산출 인증 함수는 인자 수가 다를 수 있어 둘 다 처리
  foreach f in array array['public.verify_suryang_license(character varying, character varying)',
                           'public.verify_suryang_license(character varying, character varying, jsonb)'] loop
    if to_regprocedure(f) is not null then
      execute format('alter function %s security definer', f);
      execute format('alter function %s set search_path = public', f);
    end if;
  end loop;
end $$;

-- 2) 공개 규칙 삭제
drop policy if exists "Allow license verification" on public.nomu_licenses;
drop policy if exists "Allow license activation"   on public.nomu_licenses;
drop policy if exists "Allow log insert"           on public.nomu_license_logs;
drop policy if exists "Allow log select"           on public.nomu_license_logs;
drop policy if exists "Allow all for authenticated" on public.suryang_licenses;

alter table public.nomu_licenses     enable row level security;
alter table public.nomu_license_logs enable row level security;
alter table public.suryang_licenses  enable row level security;

-- 슈퍼관리자만 (조회·생성·수정·삭제)
drop policy if exists la_admin_all on public.nomu_licenses;
create policy la_admin_all on public.nomu_licenses for all to authenticated using (public.gp_is_superadmin()) with check (public.gp_is_superadmin());
drop policy if exists la_admin_all on public.nomu_license_logs;
create policy la_admin_all on public.nomu_license_logs for all to authenticated using (public.gp_is_superadmin()) with check (public.gp_is_superadmin());
drop policy if exists la_admin_all on public.suryang_licenses;
create policy la_admin_all on public.suryang_licenses for all to authenticated using (public.gp_is_superadmin()) with check (public.gp_is_superadmin());

-- 스케치업 플러그인(licenses): 슈퍼관리자 발급·수정·삭제 (기존 조회 규칙은 그대로 둠)
alter table public.licenses enable row level security;
drop policy if exists la_admin_all on public.licenses;
create policy la_admin_all on public.licenses for all to authenticated using (public.gp_is_superadmin()) with check (public.gp_is_superadmin());

revoke all on public.nomu_licenses, public.nomu_license_logs from anon;

-- 수량산출: 배포된 프로그램(license_manager.py)이 표를 직접 읽어 인증함 → 읽기만 임시로 남김
--          쓰기·삭제는 막음. 프로그램을 verify_suryang_license 방식으로 바꿔 배포한 뒤 이 두 줄을 지우면 됨
drop policy if exists la_suryang_verify_read on public.suryang_licenses;
create policy la_suryang_verify_read on public.suryang_licenses for select to anon using (true);
revoke insert, update, delete, truncate, references, trigger on public.suryang_licenses from anon;

-- 3) 관리 함수: 로그인 안 한 사람은 못 부름 (부르더라도 표 규칙상 슈퍼관리자만 실제로 바뀜)
do $$ declare f text; begin
  foreach f in array array[
    'public.generate_nomu_license(character varying, character varying, character varying, character varying, character varying, integer, text)',
    'public.generate_suryang_license(character varying, character varying, character varying, character varying, character varying, integer, text)',
    'public.reset_nomu_machine(character varying)',
    'public.reset_suryang_machine(character varying)'] loop
    if to_regprocedure(f) is not null then
      execute format('revoke execute on function %s from public, anon', f);
      execute format('grant execute on function %s to authenticated', f);
    end if;
  end loop;
end $$;

commit;

-- =====================================================================
--  되돌리기 (문제가 생기면 이것만 실행 → 패치 전 상태로)
-- =====================================================================
-- begin;
-- alter function public.verify_nomu_license(character varying, character varying, jsonb) security invoker;
-- alter function public.verify_suryang_license(character varying, character varying) security invoker;
-- drop policy if exists la_admin_all on public.nomu_licenses;
-- drop policy if exists la_admin_all on public.nomu_license_logs;
-- drop policy if exists la_admin_all on public.suryang_licenses;
-- drop policy if exists la_admin_all on public.licenses;
-- drop policy if exists la_suryang_verify_read on public.suryang_licenses;
-- create policy "Allow license verification" on public.nomu_licenses for select using (true);
-- create policy "Allow license activation" on public.nomu_licenses for update using (true);
-- create policy "Allow log insert" on public.nomu_license_logs for insert with check (true);
-- create policy "Allow log select" on public.nomu_license_logs for select using (true);
-- create policy "Allow all for authenticated" on public.suryang_licenses for all using (true);
-- grant select, insert, update, delete on public.nomu_licenses, public.nomu_license_logs, public.suryang_licenses to anon;
-- grant execute on function public.generate_nomu_license(character varying, character varying, character varying, character varying, character varying, integer, text) to anon;
-- grant execute on function public.reset_nomu_machine(character varying) to anon;
-- commit;
