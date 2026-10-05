/* Harmless import evidence fixture. Never execute the compiled file. */
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
__declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);
EXPORT int import_fixture(void) { return (int)GetCurrentProcessId(); }
#else
#define EXPORT __attribute__((visibility("default")))
extern int fixture_sink(const char *text);
EXPORT int import_fixture(void) { return fixture_sink("benign dynamic dependency"); }
#endif
