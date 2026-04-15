-- Step 1: Create agents-access system role for every existing org
-- (permissions start empty; ReconcileSystemRoles fills them on startup)
INSERT INTO custom_roles (
    name, display_name, organization_id,
    site_permissions, org_permissions, user_permissions, member_permissions,
    is_system, created_at, updated_at
)
SELECT
    'agents-access', 'Coder Agents User', id,
    '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
    true, NOW(), NOW()
FROM organizations
WHERE NOT EXISTS (
    SELECT 1 FROM custom_roles
    WHERE custom_roles.name = 'agents-access'
      AND custom_roles.organization_id = organizations.id
);

-- Step 2: For every user who has 'agents-access' in users.rbac_roles,
-- grant the org-scoped role in each org they belong to.
UPDATE organization_members
SET roles = array_append(roles, 'agents-access')
WHERE user_id IN (
    SELECT id FROM users
    WHERE 'agents-access' = ANY(rbac_roles)
)
AND NOT ('agents-access' = ANY(roles));

-- Step 3: Remove 'agents-access' from site-level roles.
UPDATE users
SET rbac_roles = array_remove(rbac_roles, 'agents-access')
WHERE 'agents-access' = ANY(rbac_roles);

-- Step 4: Update the trigger that creates system roles for new organizations
-- to also create the agents-access system role.
CREATE OR REPLACE FUNCTION insert_organization_system_roles() RETURNS trigger AS $$
BEGIN
    INSERT INTO custom_roles (
        name, display_name, organization_id,
        site_permissions, org_permissions, user_permissions, member_permissions,
        is_system, created_at, updated_at
    ) VALUES
    (
        'organization-member',
        '',
        NEW.id,
        '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
        true, NOW(), NOW()
    ),
    (
        'organization-service-account',
        '',
        NEW.id,
        '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
        true, NOW(), NOW()
    ),
    (
        'agents-access',
        'Coder Agents User',
        NEW.id,
        '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
        true, NOW(), NOW()
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
