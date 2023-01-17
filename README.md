SysBPF is a system analysis tool built on the BPF Compiler Collection (BCC) toolkit.

WARNING: This tool is a prototype!

Usage:

`
./block-stack.py --interval 5
`

Column abbreviations:

* s: submission
* c: completion
* r, w, d: read, write, discard
* ra: read ahead
* rm, wm, dm: read merge, write merge, discard merge
* rs, ws, ds: read split, write split, discard split
* ct: count (request/s)
* st: service time (time/request)
* sz: size (sectors/request)
* bw: bandwidth (sectors/s)

Data collection:

`
./block-stack.py --interval 5 --no-header > stats.data
`

For details, please refer to the medium [article](https://medium.com/@buraks78/a-systems-engineering-attempt-to-analyze-the-linux-block-layer-with-bpf-compiler-collection-bcc-5dc695de2dbf).