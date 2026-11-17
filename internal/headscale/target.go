package headscale

// ValidateTarget checks a target the way CachingRegistry does before using it (instance id, slug rule of §14.5, API
// key present, 40-character edge token, http(s)://host[:port] admin URL). Locator implementations call it to fail
// early with their own context; the error never repeats a credential.
func ValidateTarget(t Target) error {
	_, err := validateTarget(t)
	return err
}
