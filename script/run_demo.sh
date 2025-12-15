#!/bin/bash
set -e

cleanup() {
  kill $HFC_PID
  rm -rf tmp_xx223
}
trap cleanup EXIT INT TERM

build_libpng() {
  pushd test/
  bash build_libpng.sh
  ### Prepare other fuzzers
  cd libpng/build-runtime/
  docker cp pfuzzer:/libfuzzer/libpng_libpng_read_fuzzer/libpng.tar.gz . # TODO: remove this command
  tar -zxvf libpng.tar.gz # TODO: remove this command
  popd
}

build_freetype2() {
  pushd test/
  bash build_freetype2.sh
  ### Prepare other fuzzers
  cd freetype2/build-runtime/
  docker cp pfuzzer:/libfuzzer/freetype2_ftfuzzer/freetype2.tar.gz . # TODO: remove this command
  tar -zxvf freetype2.tar.gz # TODO: remove this command
  popd
}

# Make sure that the script is run from the root directory of the project
## 0. Check argument
SKIP_BUILD=0
HFC_ONLY=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --hfc-only)
      HFC_ONLY=1
      shift
      ;;
    *)
      TARGET=$1
      shift
      ;;
  esac
done
if [ -z "$TARGET" ]; then
  echo "Usage: $0 [--skip-build] <target>"
  echo "  --skip-build    Skip compilation steps and directly run the demo"
  exit 1
fi
PROGNAME=""

if [ $SKIP_BUILD -eq 0 ]; then
  ## 1. Compile HFC
  make

  ## 2. Compile pfuzzer
  pushd pfuzzer/
  bash build.sh
  popd

  ## 3. Compile target for demo
  if [ $TARGET == "libpng" ]; then
    build_libpng
    PROGNAME=libpng_read_fuzzer
  elif [ $TARGET == "freetype2" ]; then
    build_freetype2
    PROGNAME=ftfuzzer
  else
    echo "Unknown target: $TARGET"
    exit 1
  fi
fi

if [ $TARGET == "libpng" ]; then
  PROGNAME=libpng_read_fuzzer
elif [ $TARGET == "freetype2" ]; then
  PROGNAME=ftfuzzer
else
  echo "Unknown target: $TARGET"
  exit 1
fi

## 4. Run HFC
pushd test/$TARGET/
pushd build/
DATA_FILE=$(ls ./fuzzerLogFile*.data | head -n 1)
DATA_FILE_ABS=$(realpath $DATA_FILE)
YAML_FILE=$(ls ./fuzzerLogFile*.yaml | head -n 1)
YAML_FILE_ABS=$(realpath $YAML_FILE)
popd
pushd build-runtime/
PROG_FILE=$(realpath ${PROGNAME}_cov)
popd
popd
if [ $HFC_ONLY -eq 0 ]; then
  build/hfc -calltree=$DATA_FILE_ABS -profile=$YAML_FILE_ABS -program=$PROG_FILE & HFC_PID=$!
  sleep 5
elif [ $HFC_ONLY -eq 1 ]; then
  build/hfc -calltree=$DATA_FILE_ABS -profile=$YAML_FILE_ABS -program=$PROG_FILE
fi

## 5. Run pfuzzer
if [ $HFC_ONLY -eq 0 ]; then
  mkdir -p tmp_xx223
  AFL_SKIP_CPUFREQ=1 HFC_URL=http://localhost:8080 test/${TARGET}/build-runtime/${PROGNAME} tmp_xx223/ test/${TARGET}_seeds/ -fork=2 -fuzzers=afl
fi