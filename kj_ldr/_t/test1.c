unsigned char __loader;
unsigned char __loader_end;

int main(int argc, const char *argv[]) {
	extern long loader_try(unsigned long, const char *);
	const char *lib = (argc > 1) ? argv[1] : "libz.so";
	return loader_try(0, lib);
}
