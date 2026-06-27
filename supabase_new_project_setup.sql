-- ============================================================
-- 勤怠管理アプリ  新規 Supabase プロジェクト用セットアップSQL
-- ------------------------------------------------------------
-- 新しい Supabase プロジェクトを作成したら、
-- Dashboard > SQL Editor にこのファイルの内容を貼り付けて
-- 一括実行してください（上から順に全て実行されます）。
--
-- このSQL 1本で以下がすべて構築されます:
--   - kintai テーブル（勤怠記録）
--   - profiles テーブル（表示名・請求書設定）
--   - Row Level Security（RLS）とポリシー
--   - 新規ユーザー登録時に profiles を自動作成するトリガー
--   - 管理者用の関数（ユーザー一覧取得・作成・削除）
-- ============================================================


-- ============================================================
-- 0. 必要な拡張機能
--    admin_create_user 関数のパスワード暗号化（crypt / gen_salt）に使用
-- ============================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;


-- ============================================================
-- 1. kintai テーブルの作成（勤怠記録）
--    id          : UUID の主キー（自動採番）
--    date        : 勤務日
--    start_time  : 開始時刻
--    end_time    : 終了時刻
--    break_min   : 休憩時間（分）
--    work_min    : 実労働時間（分） ※フロントで計算して保存
--    memo        : 作業内容メモ
--    user_id     : 記録の所有者（auth.users への参照）
-- ============================================================
CREATE TABLE IF NOT EXISTS kintai (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  date       date NOT NULL,
  start_time time,
  end_time   time,
  break_min  integer DEFAULT 0,
  work_min   integer DEFAULT 0,
  memo       text,
  user_id    uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz DEFAULT now()
);

-- 検索を高速化するためのインデックス
CREATE INDEX IF NOT EXISTS kintai_user_id_idx ON kintai (user_id);
CREATE INDEX IF NOT EXISTS kintai_date_idx    ON kintai (date);


-- ============================================================
-- 2. profiles テーブルの作成（ユーザーの表示名・請求書設定を管理）
-- ============================================================
CREATE TABLE IF NOT EXISTS profiles (
  id         uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name       text NOT NULL,
  created_at timestamptz DEFAULT now(),

  -- 請求書設定（発行者情報・振込先情報・時給単価）
  inv_issuer       text,   -- 発行者名
  inv_zip          text,   -- 郵便番号
  inv_address      text,   -- 住所
  inv_tel          text,   -- 電話番号
  inv_email        text,   -- メールアドレス
  inv_invoice_reg  text,   -- インボイス登録番号
  inv_rate         integer,-- 時給単価
  inv_bank         text,   -- 銀行名
  inv_branch       text,   -- 支店名
  inv_branch_no    text,   -- 支店番号
  inv_account_type text,   -- 口座種別
  inv_account_no   text,   -- 口座番号
  inv_account_name text    -- 口座名義
);


-- ============================================================
-- 3. Row Level Security (RLS) を有効化
-- ============================================================
ALTER TABLE kintai    ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles  ENABLE ROW LEVEL SECURITY;


-- ============================================================
-- 4. kintai テーブルの RLS ポリシー
--    管理者: 全行参照可（編集不可はフロントエンドで制御）
--    個人:   自分の行のみ CRUD 可
-- ============================================================
DROP POLICY IF EXISTS "kintai_select"  ON kintai;
DROP POLICY IF EXISTS "kintai_insert"  ON kintai;
DROP POLICY IF EXISTS "kintai_update"  ON kintai;
DROP POLICY IF EXISTS "kintai_delete"  ON kintai;

CREATE POLICY "kintai_select" ON kintai FOR SELECT USING (
  auth.uid() = user_id
  OR (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin'
);
CREATE POLICY "kintai_insert" ON kintai FOR INSERT WITH CHECK (
  auth.uid() = user_id
);
CREATE POLICY "kintai_update" ON kintai FOR UPDATE USING (
  auth.uid() = user_id
);
CREATE POLICY "kintai_delete" ON kintai FOR DELETE USING (
  auth.uid() = user_id
);


-- ============================================================
-- 5. profiles テーブルの RLS ポリシー
-- ============================================================
DROP POLICY IF EXISTS "profiles_select" ON profiles;
DROP POLICY IF EXISTS "profiles_insert" ON profiles;
DROP POLICY IF EXISTS "profiles_update" ON profiles;

CREATE POLICY "profiles_select" ON profiles FOR SELECT USING (
  auth.uid() = id
  OR (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin'
);
CREATE POLICY "profiles_insert" ON profiles FOR INSERT WITH CHECK (
  auth.uid() = id
);
CREATE POLICY "profiles_update" ON profiles FOR UPDATE USING (
  auth.uid() = id
);


-- ============================================================
-- 6. 新規ユーザー登録時に profiles を自動作成するトリガー
--    auth.users に行が追加されると profiles に同じ id の行を作成する。
--    name は user_metadata の name → なければメールアドレスの @ 前を使用。
-- ============================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO public.profiles (id, name)
  VALUES (
    NEW.id,
    COALESCE(
      NEW.raw_user_meta_data ->> 'name',
      split_part(NEW.email, '@', 1)
    )
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();


-- ============================================================
-- 7. ユーザー管理画面用 SQL 関数（管理者がユーザー一覧を取得）
--    ※ この関数を実行しないとユーザー管理画面の一覧が表示されません
-- ============================================================
CREATE OR REPLACE FUNCTION list_users_for_admin()
RETURNS TABLE (
  id               uuid,
  email            text,
  name             text,
  role             text,
  created_at       timestamptz,
  email_confirmed  bool
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  -- 管理者のみ実行可能
  IF (auth.jwt() -> 'user_metadata' ->> 'role') <> 'admin' THEN
    RAISE EXCEPTION 'admin only';
  END IF;

  RETURN QUERY
  SELECT
    au.id::uuid,
    au.email::text,
    p.name::text,
    COALESCE(au.raw_user_meta_data ->> 'role', 'user')::text,
    au.created_at::timestamptz,
    (au.email_confirmed_at IS NOT NULL)::bool
  FROM auth.users au
  LEFT JOIN public.profiles p ON p.id = au.id
  ORDER BY au.created_at;
END;
$$;

-- 認証済みユーザーに実行権限を付与（関数内で管理者チェックあり）
GRANT EXECUTE ON FUNCTION list_users_for_admin() TO authenticated;


-- ============================================================
-- 8. ユーザー作成関数
--    SECURITY DEFINER で postgres 権限で実行するため
--    サービスロールキー・Edge Function・Vault いずれも不要
-- ============================================================
CREATE OR REPLACE FUNCTION admin_create_user(
  p_email    text,
  p_password text,
  p_role     text DEFAULT 'user'
)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := gen_random_uuid();
BEGIN
  IF (auth.jwt() -> 'user_metadata' ->> 'role') <> 'admin' THEN
    RAISE EXCEPTION 'admin only';
  END IF;

  INSERT INTO auth.users (
    id, aud, role, email,
    encrypted_password,
    email_confirmed_at,
    raw_app_meta_data,
    raw_user_meta_data,
    created_at, updated_at
  ) VALUES (
    v_uid,
    'authenticated',
    'authenticated',
    p_email,
    extensions.crypt(p_password, extensions.gen_salt('bf')),
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    jsonb_build_object('role', p_role),
    now(),
    now()
  );

  RETURN jsonb_build_object('id', v_uid, 'email', p_email);
EXCEPTION
  WHEN unique_violation THEN
    RAISE EXCEPTION 'このメールアドレスは既に使用されています: %', p_email;
END;
$$;

GRANT EXECUTE ON FUNCTION admin_create_user(text, text, text) TO authenticated;


-- ============================================================
-- 9. ユーザー削除関数
-- ============================================================
CREATE OR REPLACE FUNCTION admin_delete_user(p_user_id uuid)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF (auth.jwt() -> 'user_metadata' ->> 'role') <> 'admin' THEN
    RAISE EXCEPTION 'admin only';
  END IF;

  IF p_user_id = auth.uid() THEN
    RAISE EXCEPTION '自分自身は削除できません';
  END IF;

  DELETE FROM auth.users WHERE id = p_user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'ユーザーが見つかりません';
  END IF;

  RETURN jsonb_build_object('success', true);
END;
$$;

GRANT EXECUTE ON FUNCTION admin_delete_user(uuid) TO authenticated;


-- ============================================================
-- ▼▼▼ ここから先は SQL 実行後に Dashboard 上で行う手動設定 ▼▼▼
-- ============================================================
--
-- 【セルフサインアップの無効化（管理者のみユーザー作成可）】
--   Dashboard > Authentication > Sign In / Providers > Email
--     - Enable email signup: OFF
--
-- 【最初の管理者ユーザーの作成】
--   1) Dashboard > Authentication > Users > 「Add user」
--      メールアドレスと仮パスワードを入力して作成
--      （上記トリガーにより profiles も自動作成されます）
--   2) 作成したユーザーを選択 >「Edit user」
--      User Metadata に以下を入力して保存:
--        {"role": "admin"}
--
-- 【2人目以降のユーザー】
--   管理者ログイン後、アプリのユーザー管理画面から作成できます
--   （admin_create_user 関数が使われます）。
-- ============================================================
