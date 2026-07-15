use std::process::Command;

pub(crate) fn remove_environment_variables(command: &mut Command, variables: &[String]) {
    for variable in variables {
        command.env_remove(variable);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn removes_environment_variables_from_child_processes() {
        let variables = vec!["SECENV_TEST_SEALED_SECRET".to_string()];
        let mut command = Command::new("sh");
        command
            .args(["-c", "[ -z \"${SECENV_TEST_SEALED_SECRET+x}\" ]"])
            .env("SECENV_TEST_SEALED_SECRET", "must-not-leak");

        remove_environment_variables(&mut command, &variables);
        assert!(command.status().expect("failed to run test command").success());
    }
}
