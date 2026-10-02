from time import perf_counter

from xax_compiler import Kind, StoreReader, bits_type, constant, object_with_refs, write_store


def main(count=10_000):
    b64 = bits_type(64)
    constants = [constant(b64, value) for value in range(count)]
    module = object_with_refs(Kind.MODULE, constants)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    started = perf_counter()
    encoded = write_store(root.cid, [b64, *constants, module, root])
    written = perf_counter() - started
    started = perf_counter()
    reader = StoreReader(encoded)
    reader.get(constants[-1].cid)
    read = perf_counter() - started
    print({"objects": count + 3, "bytes": len(encoded), "write_seconds": written, "parse_and_lookup_seconds": read})


if __name__ == "__main__":
    main()
