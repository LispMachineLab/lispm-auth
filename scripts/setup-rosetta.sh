#!/bin/bash
# CI only: run under arch -x86_64 /bin/bash on an Apple Silicon hosted runner.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "$(uname -s)" == Darwin ]]
[[ "$(uname -m)" == x86_64 ]]
[[ "$(sysctl -in sysctl.proc_translated)" == 1 ]]
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH DYLD_LIBRARY_PATH \
  DYLD_FALLBACK_LIBRARY_PATH CFLAGS CPPFLAGS CXXFLAGS LDFLAGS PKG_CONFIG_PATH
# Pinned bootstrap, never run the moving install.sh; only on disposable CI hosts.
BREW_COMMIT=96d2a24a745d3f7dcf41ccdbb6f67243b54c27a4
if [[ ! -x /usr/local/bin/brew ]]; then
  for dir in Homebrew Cellar Caskroom Frameworks bin etc include lib opt sbin share var; do
    sudo mkdir -p "/usr/local/$dir"
    sudo chown "$(id -un):$(id -gn)" "/usr/local/$dir"
  done
  git init /usr/local/Homebrew
  git -C /usr/local/Homebrew remote add origin https://github.com/Homebrew/brew.git
  git -C /usr/local/Homebrew fetch --depth=1 origin "$BREW_COMMIT"
  git -C /usr/local/Homebrew checkout --detach FETCH_HEAD
  ln -s ../Homebrew/bin/brew /usr/local/bin/brew
fi
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1
[[ "$(brew --prefix)" == /usr/local ]]
brew config
brew install --force-bottle ecl libsodium pkgconf texinfo
for formula in ecl libsodium gmp bdw-gc; do
  prefix="$(brew --prefix "$formula")"
  [[ "$prefix" == /usr/local/* ]]
  while IFS= read -r -d '' library; do
    lipo -verify_arch x86_64 "$library"
  done < <(find "$prefix/lib" -name '*.dylib' -type f -print0)
done
lipo -verify_arch x86_64 "$(command -v ecl)"
SODIUM_PREFIX="$(brew --prefix libsodium)"
lipo -verify_arch x86_64 "$SODIUM_PREFIX/lib/libsodium.a"
TEXINFO_PREFIX="$(brew --prefix texinfo)"
export PATH="$TEXINFO_PREFIX/bin:$PATH"
# Compile Emacs inside the same translated shell; never borrow an ARM cache.
EMACS_PREFIX="$RUNNER_TEMP/emacs-x86_64"
if [[ "${EMACS_CACHE_HIT:-false}" != true ]]; then
  curl --fail --location --retry 3 https://ftp.gnu.org/gnu/emacs/emacs-30.1.tar.xz -o "$RUNNER_TEMP/emacs-x86_64.tar.xz"
  tar -xf "$RUNNER_TEMP/emacs-x86_64.tar.xz" -C "$RUNNER_TEMP"
  (
    cd "$RUNNER_TEMP/emacs-30.1"
    export CFLAGS='-O2 -arch x86_64' LDFLAGS='-arch x86_64'
    ./configure --prefix="$EMACS_PREFIX" --build=x86_64-apple-darwin \
      --without-x --without-ns --without-native-compilation --without-tree-sitter \
      --without-dbus --without-sound --without-pop --without-mailutils \
      --without-compress-install
    make -j3
    make install
  )
fi
lipo -verify_arch x86_64 "$EMACS_PREFIX/bin/emacs"
"$EMACS_PREFIX/bin/emacs" -Q --batch --eval \
  '(unless (and (string-match-p "x86_64" system-configuration) (fboundp (quote zlib-decompress-region))) (error "Expected Intel Emacs with zlib"))'
{
  echo "SODIUM_PREFIX=$SODIUM_PREFIX"
  echo 'HOMEBREW_NO_AUTO_UPDATE=1'
  echo 'HOMEBREW_NO_ANALYTICS=1'
} >> "$GITHUB_ENV"
# Override, do not append to, the ARM runner's tool search path.
echo "PATH=$EMACS_PREFIX/bin:$(brew --prefix texinfo)/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" >> "$GITHUB_ENV"
ecl --norc --eval '(progn (format t "~a ~a~%" (lisp-implementation-type) (machine-type)) (ext:quit 0))'
