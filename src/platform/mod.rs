/// Information about the current operating system and architecture
pub struct PlatformInfo;

impl PlatformInfo {
    pub const OS_NAME: &'static str = if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "Other"
    };

    pub const ARCH: &'static str = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    pub fn display_summary() -> String {
        format!("{} {}", Self::OS_NAME, Self::ARCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_info() {
        assert!(!PlatformInfo::OS_NAME.is_empty());
        assert!(!PlatformInfo::ARCH.is_empty());
    }
}
