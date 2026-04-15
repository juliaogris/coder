-- Step 1: Move agents-access back to site-level for any user who has it in any org.
UPDATE users
SET rbac_roles = array_append(rbac_roles, 'agents-access')
WHERE id IN (
    SELECT DISTINCT user_id FROM organization_members
    WHERE 'agents-access' = ANY(roles)
)
AND NOT ('agents-access' = ANY(rbac_roles));

-- Step 2: Remove from org memberships.
UPDATE organization_members
SET roles = array_remove(roles, 'agents-access')
WHERE 'agents-access' = ANY(roles);

-- Step 3: Remove system role entries.
DELETE FROM custom_roles
WHERE name = 'agents-access' AND is_system = true;

-- Step 4: Restore the original trigger without agents-access.
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
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
