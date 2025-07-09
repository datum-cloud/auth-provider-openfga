package openfga

// IAM Type constants for OpenFGA authorization model
const (
	// IAM Types
	TypeInternalUser      = "iam.miloapis.com/InternalUser"
	TypeInternalUserGroup = "iam.miloapis.com/InternalUserGroup"
	TypeInternalRole      = "iam.miloapis.com/InternalRole"
	TypeRole              = "iam.miloapis.com/Role"
	TypeRoleBinding       = "iam.miloapis.com/RoleBinding"
	TypeRoot              = "iam.miloapis.com/Root"

	// IAM Relations
	RelationRoleBinding  = "iam.miloapis.com/RoleBinding"
	RelationRootBinding  = "iam.miloapis.com/RootBinding"
	RelationInternalRole = "iam.miloapis.com/InternalRole"
	RelationInternalUser = "iam.miloapis.com/InternalUser"

	// Standard relations
	RelationMember   = "member"
	RelationAssignee = "assignee"
	RelationParent   = "parent"

	// OpenFGA metadata
	SourceFile = "dynamically_managed_iam_datumapis_com.fga"
	Module     = "iam.miloapis.com"
)
