pub(crate) mod agent_jobs;
pub(crate) mod apply_patch;
mod dynamic;
mod goal;
mod list_dir;
mod mcp;
mod mcp_resource;
pub(crate) mod multi_agents;
pub(crate) mod multi_agents_common;
pub(crate) mod multi_agents_v2;
mod plan;
mod request_permissions;
mod request_user_input;
mod shell;
mod test_sync;
mod tool_search;
mod tool_suggest;
mod unavailable_tool;
pub(crate) mod unified_exec;
mod view_image;

use codex_sandboxing::policy_transforms::intersect_permission_profiles;
use codex_sandboxing::policy_transforms::merge_permission_profiles;
use codex_sandboxing::policy_transforms::normalize_additional_permissions;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_absolute_path::AbsolutePathBufGuard;
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;

use crate::function_tool::FunctionCallError;
use crate::sandboxing::SandboxPermissions;
use crate::session::session::Session;
use crate::session::turn_context::TurnContext;
pub(crate) use crate::tools::code_mode::CodeModeExecuteHandler;
pub(crate) use crate::tools::code_mode::CodeModeWaitHandler;
pub use apply_patch::ApplyPatchHandler;
use codex_protocol::models::AdditionalPermissionProfile;
use codex_protocol::protocol::AskForApproval;
pub use dynamic::DynamicToolHandler;
pub use goal::GoalHandler;
pub use list_dir::ListDirHandler;
pub use mcp::McpHandler;
pub use mcp_resource::McpResourceHandler;
pub use plan::PlanHandler;
pub use request_permissions::RequestPermissionsHandler;
pub use request_user_input::RequestUserInputHandler;
pub use shell::ShellCommandHandler;
pub use shell::ShellHandler;
pub use test_sync::TestSyncHandler;
pub use tool_search::ToolSearchHandler;
pub use tool_suggest::ToolSuggestHandler;
pub use unavailable_tool::UnavailableToolHandler;
pub(crate) use unavailable_tool::unavailable_tool_message;
pub use unified_exec::UnifiedExecHandler;
pub use view_image::ViewImageHandler;

fn parse_arguments<T>(arguments: &str) -> Result<T, FunctionCallError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(arguments).map_err(|err| {
        FunctionCallError::RespondToModel(format!("failed to parse function arguments: {err}"))
    })
}

fn parse_arguments_with_base_path<T>(
    arguments: &str,
    base_path: &AbsolutePathBuf,
) -> Result<T, FunctionCallError>
where
    T: for<'de> Deserialize<'de>,
{
    let _guard = AbsolutePathBufGuard::new(base_path);
    parse_arguments(arguments)
}

pub(crate) struct ProcessToolEnvironment {
    pub(crate) environment: Arc<codex_exec_server::Environment>,
    pub(crate) cwd: AbsolutePathBuf,
}

impl ProcessToolEnvironment {
    pub(crate) fn resolve_workdir(&self, workdir: Option<&str>) -> AbsolutePathBuf {
        workdir
            .filter(|workdir| !workdir.is_empty())
            .map_or_else(|| self.cwd.clone(), |workdir| self.cwd.join(workdir))
    }
}

pub(crate) struct ProcessToolCall<T> {
    pub(crate) params: T,
    pub(crate) target_environment: ProcessToolEnvironment,
    pub(crate) cwd: AbsolutePathBuf,
}

#[derive(Deserialize)]
struct ProcessToolRoutingArgs {
    environment_id: Option<String>,
    workdir: Option<String>,
}

pub(crate) fn resolve_process_tool_environment(
    turn: &TurnContext,
    environment_id: Option<&str>,
) -> Result<Option<ProcessToolEnvironment>, FunctionCallError> {
    // The model only needs to provide an id once there are multiple choices.
    if environment_id.is_none() && turn.environments.len() <= 1 {
        return Ok(turn
            .environments
            .primary()
            .map(|environment| ProcessToolEnvironment {
                environment: Arc::clone(&environment.environment),
                cwd: environment.cwd.clone(),
            }));
    }

    let selected_environment = turn
        .environments
        .selected_environment(environment_id)
        .map_err(FunctionCallError::RespondToModel)?;
    if let Some(environment) = selected_environment {
        return Ok(Some(ProcessToolEnvironment {
            environment: Arc::clone(&environment.environment),
            cwd: environment.cwd.clone(),
        }));
    }
    Ok(None)
}

pub(crate) fn resolve_process_tool_call_from_arguments<T>(
    turn: &TurnContext,
    arguments: &str,
    unavailable_message: &'static str,
) -> Result<ProcessToolCall<T>, FunctionCallError>
where
    T: for<'de> Deserialize<'de>,
{
    let routing_args: ProcessToolRoutingArgs = parse_arguments(arguments)?;
    let target_environment =
        resolve_process_tool_environment(turn, routing_args.environment_id.as_deref())?
            .ok_or_else(|| FunctionCallError::RespondToModel(unavailable_message.to_string()))?;
    let cwd = target_environment.resolve_workdir(routing_args.workdir.as_deref());
    let params = parse_arguments_with_base_path(arguments, &cwd)?;

    Ok(ProcessToolCall {
        params,
        target_environment,
        cwd,
    })
}

/// Validates feature/policy constraints for `with_additional_permissions` and
/// normalizes any path-based permissions. Errors if the request is invalid.
pub(crate) fn normalize_and_validate_additional_permissions(
    additional_permissions_allowed: bool,
    approval_policy: AskForApproval,
    sandbox_permissions: SandboxPermissions,
    additional_permissions: Option<AdditionalPermissionProfile>,
    permissions_preapproved: bool,
    _cwd: &Path,
) -> Result<Option<AdditionalPermissionProfile>, String> {
    let uses_additional_permissions = matches!(
        sandbox_permissions,
        SandboxPermissions::WithAdditionalPermissions
    );

    if !permissions_preapproved
        && !additional_permissions_allowed
        && (uses_additional_permissions || additional_permissions.is_some())
    {
        return Err(
            "additional permissions are disabled; enable `features.exec_permission_approvals` before using `with_additional_permissions`"
                .to_string(),
        );
    }

    if uses_additional_permissions {
        if !permissions_preapproved && !matches!(approval_policy, AskForApproval::OnRequest) {
            return Err(format!(
                "approval policy is {approval_policy:?}; reject command — you cannot request additional permissions unless the approval policy is OnRequest"
            ));
        }
        let Some(additional_permissions) = additional_permissions else {
            return Err(
                "missing `additional_permissions`; provide at least one of `network` or `file_system` when using `with_additional_permissions`"
                    .to_string(),
            );
        };
        let normalized = normalize_additional_permissions(additional_permissions)?;
        if normalized.is_empty() {
            return Err(
                "`additional_permissions` must include at least one requested permission in `network` or `file_system`"
                    .to_string(),
            );
        }
        return Ok(Some(normalized));
    }

    if additional_permissions.is_some() {
        Err(
            "`additional_permissions` requires `sandbox_permissions` set to `with_additional_permissions`"
                .to_string(),
        )
    } else {
        Ok(None)
    }
}

pub(super) struct EffectiveAdditionalPermissions {
    pub sandbox_permissions: SandboxPermissions,
    pub additional_permissions: Option<AdditionalPermissionProfile>,
    pub permissions_preapproved: bool,
}

pub(super) fn implicit_granted_permissions(
    sandbox_permissions: SandboxPermissions,
    additional_permissions: Option<&AdditionalPermissionProfile>,
    effective_additional_permissions: &EffectiveAdditionalPermissions,
) -> Option<AdditionalPermissionProfile> {
    if !sandbox_permissions.uses_additional_permissions()
        && !matches!(sandbox_permissions, SandboxPermissions::RequireEscalated)
        && additional_permissions.is_none()
    {
        effective_additional_permissions
            .additional_permissions
            .clone()
    } else {
        None
    }
}

pub(super) async fn apply_granted_turn_permissions(
    session: &Session,
    cwd: &std::path::Path,
    sandbox_permissions: SandboxPermissions,
    additional_permissions: Option<AdditionalPermissionProfile>,
) -> EffectiveAdditionalPermissions {
    if matches!(sandbox_permissions, SandboxPermissions::RequireEscalated) {
        return EffectiveAdditionalPermissions {
            sandbox_permissions,
            additional_permissions,
            permissions_preapproved: false,
        };
    }

    let granted_session_permissions = session.granted_session_permissions().await;
    let granted_turn_permissions = session.granted_turn_permissions().await;
    let granted_permissions = merge_permission_profiles(
        granted_session_permissions.as_ref(),
        granted_turn_permissions.as_ref(),
    );
    let effective_permissions = merge_permission_profiles(
        additional_permissions.as_ref(),
        granted_permissions.as_ref(),
    );
    let permissions_preapproved = match (effective_permissions.as_ref(), granted_permissions) {
        (Some(effective_permissions), Some(granted_permissions)) => {
            permissions_are_preapproved(effective_permissions, granted_permissions, cwd)
        }
        _ => false,
    };

    let sandbox_permissions =
        if effective_permissions.is_some() && !sandbox_permissions.uses_additional_permissions() {
            SandboxPermissions::WithAdditionalPermissions
        } else {
            sandbox_permissions
        };

    EffectiveAdditionalPermissions {
        sandbox_permissions,
        additional_permissions: effective_permissions,
        permissions_preapproved,
    }
}

fn permissions_are_preapproved(
    effective_permissions: &AdditionalPermissionProfile,
    granted_permissions: AdditionalPermissionProfile,
    cwd: &Path,
) -> bool {
    let materialized_effective_permissions = intersect_permission_profiles(
        effective_permissions.clone(),
        effective_permissions.clone(),
        cwd,
    );
    intersect_permission_profiles(effective_permissions.clone(), granted_permissions, cwd)
        == materialized_effective_permissions
}

#[cfg(test)]
mod tests {
    use super::EffectiveAdditionalPermissions;
    use super::ProcessToolRoutingArgs;
    use super::implicit_granted_permissions;
    use super::normalize_and_validate_additional_permissions;
    use super::parse_arguments;
    use super::parse_arguments_with_base_path;
    use super::permissions_are_preapproved;
    use crate::sandboxing::SandboxPermissions;
    use codex_protocol::models::AdditionalPermissionProfile;
    use codex_protocol::models::FileSystemPermissions;
    use codex_protocol::models::NetworkPermissions;
    use codex_protocol::models::ShellCommandToolCallParams;
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::permissions::FileSystemSpecialPath;
    use codex_protocol::protocol::AskForApproval;
    use codex_protocol::protocol::GranularApprovalConfig;
    use codex_sandboxing::policy_transforms::intersect_permission_profiles;
    use codex_sandboxing::policy_transforms::merge_permission_profiles;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    fn network_permissions() -> AdditionalPermissionProfile {
        AdditionalPermissionProfile {
            network: Some(NetworkPermissions {
                enabled: Some(true),
            }),
            ..Default::default()
        }
    }

    fn file_system_permissions(path: &std::path::Path) -> AdditionalPermissionProfile {
        AdditionalPermissionProfile {
            file_system: Some(FileSystemPermissions::from_read_write_roots(
                /*read*/ None,
                Some(vec![
                    AbsolutePathBuf::from_absolute_path(path).expect("absolute path"),
                ]),
            )),
            ..Default::default()
        }
    }

    #[test]
    fn process_tool_routing_does_not_require_typed_argument_parsing() {
        let arguments = serde_json::json!({
            "command": "touch relative-write.txt",
            "workdir": "nested",
            "environment_id": "remote",
            "sandbox_permissions": SandboxPermissions::WithAdditionalPermissions,
            "additional_permissions": {
                "file_system": {
                    "write": ["."]
                }
            }
        })
        .to_string();

        let routing_args: ProcessToolRoutingArgs =
            parse_arguments(&arguments).expect("routing args should parse");

        assert_eq!(routing_args.environment_id, Some("remote".to_string()));
        assert_eq!(routing_args.workdir, Some("nested".to_string()));
    }

    #[test]
    fn shell_command_args_resolve_relative_additional_permissions_against_workdir_base() {
        let workspace = tempdir().expect("tempdir");
        let nested = workspace.path().join("nested");
        std::fs::create_dir_all(&nested).expect("create nested directory");
        let base = AbsolutePathBuf::from_absolute_path(&nested).expect("absolute nested path");

        let arguments = serde_json::json!({
            "command": "touch relative-write.txt",
            "workdir": "nested",
            "sandbox_permissions": SandboxPermissions::WithAdditionalPermissions,
            "additional_permissions": {
                "file_system": {
                    "write": ["."]
                }
            }
        })
        .to_string();

        let params: ShellCommandToolCallParams =
            parse_arguments_with_base_path(&arguments, &base).expect("shell args should parse");

        assert_eq!(
            params.additional_permissions,
            Some(AdditionalPermissionProfile {
                file_system: Some(FileSystemPermissions::from_read_write_roots(
                    /*read*/ None,
                    Some(vec![base]),
                )),
                ..Default::default()
            })
        );
    }

    #[test]
    fn preapproved_permissions_work_when_request_permissions_tool_is_enabled_without_exec_permission_approvals_feature()
     {
        let cwd = tempdir().expect("tempdir");

        let normalized = normalize_and_validate_additional_permissions(
            /*additional_permissions_allowed*/ false,
            AskForApproval::Granular(GranularApprovalConfig {
                sandbox_approval: true,
                rules: true,
                skill_approval: true,
                request_permissions: false,
                mcp_elicitations: true,
            }),
            SandboxPermissions::WithAdditionalPermissions,
            Some(network_permissions()),
            /*permissions_preapproved*/ true,
            cwd.path(),
        )
        .expect("preapproved permissions should be allowed");

        assert_eq!(normalized, Some(network_permissions()));
    }

    #[test]
    fn fresh_additional_permissions_still_require_exec_permission_approvals_feature() {
        let cwd = tempdir().expect("tempdir");

        let err = normalize_and_validate_additional_permissions(
            /*additional_permissions_allowed*/ false,
            AskForApproval::OnRequest,
            SandboxPermissions::WithAdditionalPermissions,
            Some(network_permissions()),
            /*permissions_preapproved*/ false,
            cwd.path(),
        )
        .expect_err("fresh inline permission requests should remain disabled");

        assert_eq!(
            err,
            "additional permissions are disabled; enable `features.exec_permission_approvals` before using `with_additional_permissions`"
        );
    }

    #[test]
    fn implicit_sticky_grants_bypass_inline_permission_validation() {
        let cwd = tempdir().expect("tempdir");
        let granted_permissions = file_system_permissions(cwd.path());
        let implicit_permissions = implicit_granted_permissions(
            SandboxPermissions::UseDefault,
            /*additional_permissions*/ None,
            &EffectiveAdditionalPermissions {
                sandbox_permissions: SandboxPermissions::WithAdditionalPermissions,
                additional_permissions: Some(granted_permissions.clone()),
                permissions_preapproved: false,
            },
        );

        assert_eq!(implicit_permissions, Some(granted_permissions));
    }

    #[test]
    fn explicit_inline_permissions_do_not_use_implicit_sticky_grant_path() {
        let cwd = tempdir().expect("tempdir");
        let requested_permissions = file_system_permissions(cwd.path());
        let implicit_permissions = implicit_granted_permissions(
            SandboxPermissions::WithAdditionalPermissions,
            Some(&requested_permissions),
            &EffectiveAdditionalPermissions {
                sandbox_permissions: SandboxPermissions::WithAdditionalPermissions,
                additional_permissions: Some(requested_permissions.clone()),
                permissions_preapproved: false,
            },
        );

        assert_eq!(implicit_permissions, None);
    }

    #[test]
    fn relative_deny_glob_grants_remain_preapproved_after_materialization() {
        let cwd = tempdir().expect("tempdir");
        let requested_permissions = AdditionalPermissionProfile {
            file_system: Some(FileSystemPermissions {
                entries: vec![
                    FileSystemSandboxEntry {
                        path: FileSystemPath::Special {
                            value: FileSystemSpecialPath::project_roots(/*subpath*/ None),
                        },
                        access: FileSystemAccessMode::Write,
                    },
                    FileSystemSandboxEntry {
                        path: FileSystemPath::GlobPattern {
                            pattern: "**/*.env".to_string(),
                        },
                        access: FileSystemAccessMode::None,
                    },
                ],
                glob_scan_max_depth: None,
            }),
            ..Default::default()
        };
        let stored_grant = intersect_permission_profiles(
            requested_permissions.clone(),
            requested_permissions.clone(),
            cwd.path(),
        );
        let effective_permissions =
            merge_permission_profiles(Some(&requested_permissions), Some(&stored_grant))
                .expect("merged permissions");

        assert!(permissions_are_preapproved(
            &effective_permissions,
            stored_grant,
            cwd.path(),
        ));
    }
}
