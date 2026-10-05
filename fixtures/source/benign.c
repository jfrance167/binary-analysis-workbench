/* Original benign fixture; compiled for analysis, never executed. */
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif
#define NOINLINE __attribute__((noinline))
EXPORT const char fixture_marker[] = "BINARY_WORKBENCH_BENIGN_FIXTURE";
EXPORT const char fixture_url[] = "https://example.invalid/learning";
EXPORT const char fixture_html[] = "<script>alert('fixture')</script>\033[31m";
EXPORT const unsigned short fixture_wide[] = { 'W','I','D','E','_','F','I','X','T','U','R','E',0 };

EXPORT NOINLINE int branch_fixture(int x) {
    if (x > 10) return x + 7;
    return x - 3;
}

EXPORT NOINLINE const char *string_fixture(int x) {
    return x ? fixture_marker : fixture_url;
}

EXPORT NOINLINE int entry_fixture(void) {
    return branch_fixture(12) + (int)string_fixture(1)[0];
}
