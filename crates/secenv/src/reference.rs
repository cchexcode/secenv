use {
    crate::args::ClapArgumentLoader,
    anyhow::{
        Context,
        Result,
    },
    clap_complete::Shell,
    clap_mangen::Man,
    std::{
        fs::File,
        io::Write,
        path::Path,
    },
};

/// Generates manpages, markdown docs, and shell completions from the CLI
/// definition.
pub(crate) struct ReferenceBuilder;

impl ReferenceBuilder {
    pub(crate) fn build_shell_completion(&self, outdir: &Path, shell: &Shell) -> Result<()> {
        let mut app = ClapArgumentLoader::root_command();
        clap_complete::generate_to(*shell, &mut app, env!("CARGO_PKG_NAME"), outdir)
            .with_context(|| format!("Failed to generate completion in '{}'", outdir.display()))?;
        Ok(())
    }

    pub(crate) fn build_markdown(&self, outdir: &Path) -> Result<()> {
        for (name, command) in self.collect_commands() {
            let path = outdir.join(format!("{}.md", name));
            let mut file = File::create(&path)
                .with_context(|| format!("Failed to create Markdown reference '{}'", path.display()))?;
            file.write_all(clap_markdown::help_markdown_command(&command).as_bytes())
                .with_context(|| format!("Failed to write Markdown reference '{}'", path.display()))?;
        }
        Ok(())
    }

    pub(crate) fn build_manpages(&self, outdir: &Path) -> Result<()> {
        for (name, command) in self.collect_commands() {
            let path = outdir.join(format!("{}.1", name));
            let mut file =
                File::create(&path).with_context(|| format!("Failed to create manpage '{}'", path.display()))?;
            Man::new(command)
                .render(&mut file)
                .with_context(|| format!("Failed to render manpage '{}'", path.display()))?;
        }
        Ok(())
    }

    fn collect_commands(&self) -> Vec<(String, clap::Command)> {
        let root = ClapArgumentLoader::root_command();
        let mut pending = vec![(root.get_name().to_string(), root)];
        let mut commands = Vec::new();
        while let Some((name, command)) = pending.pop() {
            let subcommands: Vec<_> = command.get_subcommands().cloned().collect();
            for subcommand in subcommands.into_iter().rev() {
                pending.push((format!("{}-{}", name, subcommand.get_name()), subcommand.clone()));
            }
            commands.push((name, command));
        }
        commands
    }
}
