# Formula shape follows https://docs.brew.sh/Language-Specific-Formulae (Node section)
# and the homebrew-core npm-CLI formulas typescript.rb and gtop.rb: install the npm
# registry tarball into libexec via std_npm_args, then symlink the bin stubs.
# std_npm_args disables npm lifecycle scripts; residoo has none and zero dependencies,
# so npm only unpacks the published package.
class Residoo < Formula
  desc "Find secrets leaking through AI coding agent session history"
  homepage "https://github.com/dandovdub/residoo"
  url "https://registry.npmjs.org/residoo/-/residoo-0.4.6.tgz"
  # sha256 of the real published tarball: curl -sL <url> | shasum -a 256
  sha256 "0eb2a2be4d6fa441352fdd0bfe5f671d8d65290e49e836717662131674d86201"
  license "MIT"

  depends_on "node"

  def install
    system "npm", "install", *std_npm_args
    bin.install_symlink libexec.glob("bin/*")
  end

  test do
    system bin/"residoo", "--help"
    assert_match "session history", shell_output("#{bin}/residoo --help")
  end
end
