-- ============================================================
-- 勤怠管理アプリ Supabase 認証設定SQL
-- Supabase Dashboard > SQL Editor で実行してください
-- ============================================================

-- 1. kintaiテーブルに user_id 列を追加
ALTER TABLE kintai ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES auth.users(id);

-- 2. profilesテーブルを作成（ユーザーの表示名を管理）
CREATE TABLE IF NOT EXISTS profiles (
  id         uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name       text NOT NULL,
  created_at timestamptz DEFAULT now()
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
-- 6. 既存データをあなたのアカウントに紐付ける場合
--    SupabaseダッシュボードのAuthentication > Usersから
--    あなたのユーザーIDを確認し、下記を編集して実行してください
-- ============================================================
-- UPDATE kintai SET user_id = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' WHERE user_id IS NULL;

-- ============================================================
-- 【管理者ユーザーの設定方法】
-- Supabase Dashboard > Authentication > Users
-- 対象ユーザーを選択 > 「Edit」
-- User Metadata に以下を入力して保存:
--   {"role": "admin"}
-- ============================================================

-- ============================================================
-- 【ユーザー作成方法（セルフサインアップは無効化）】
-- Supabase Dashboard > Authentication > Providers
-- Email > 「Confirm email」と「Enable email signup」の設定:
--   - Enable email signup: OFF（管理者のみ作成可能）
-- Supabase Dashboard > Authentication > Users > 「Add user」
-- メールアドレスと仮パスワードを設定して作成
-- ============================================================

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
    au.id,
    au.email,
    p.name,
    COALESCE(au.raw_user_meta_data ->> 'role', 'user'),
    au.created_at,
    (au.email_confirmed_at IS NOT NULL)
  FROM auth.users au
  LEFT JOIN public.profiles p ON p.id = au.id
  ORDER BY au.created_at;
END;
$$;

-- 認証済みユーザーに実行権限を付与（RLS 内で管理者チェックあり）
GRANT EXECUTE ON FUNCTION list_users_for_admin() TO authenticated;
