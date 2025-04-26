#!/bin/sh

set -e

isbrokenplatform() {
  case "${BUILD_OS}" in
  debian:*)
    case "${TARGETPLATFORM}" in
    linux/386 | linux/arm/v7 | linux/mips64le | linux/ppc64le | linux/s390x)
      exit 1
      ;;
    esac
    ;;
  ubuntu*)
    case "${TARGETPLATFORM}" in
    linux/arm/v7 | linux/ppc64le | linux/s390x | linux/arm64)
      exit 1
      ;;
    esac
    ;;
  esac
  exit 0
}

fltplatforms() {
   case "${BUILD_OS}" in
   debian:*)
     FILT="grep -v -e ^linux/arm/v5\$" # broken 64-bit stdatomics
     ;;
   *)
     FILT="cat"
     ;;
  esac
  ${FILT}
}

platformopts() {
  out="COMPILER=clang-${LLVM_VER} LINKER=lld-${LLVM_VER}"
  case "${BUILD_OS}" in
  debian:*)
    case "${TARGETPLATFORM}" in
    linux/ppc64le | linux/arm/v7 | linux/mips64le | linux/arm/v5)
      out="COMPILER=clang-${LLVM_VER_OLD} LINKER=lld-${LLVM_VER_OLD}"
      ;;
    esac
    ;;
  ubuntu*)
    case "${TARGETPLATFORM}" in
    linux/arm64/v8)
      out="${out} QEMU_CPU=cortex-a53"
      ;;
    esac
  esac
  echo "${out}"
  echo "${@}"
}

case "${1}" in
platformopts)
  shift
  platformopts "${@}"
  ;;
fltplatforms)
  fltplatforms
  ;;
isbrokenplatform)
  isbrokenplatform
  ;;
*)
  echo "usage: `basename "${0}"` (platformopts|fltplatforms) [opts]" 2>&1
  exit 1
  ;;
esac
