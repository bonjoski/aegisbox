# typed: false
# frozen_string_literal: true

class Aegisbox < Formula
  desc "Unbreakable AI Execution Sandbox & Adversarial Range Engine"
  homepage "https://github.com/bonjoski/aegisbox"
  url "https://github.com/bonjoski/aegisbox/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  license "MIT"
  head "https://github.com/bonjoski/aegisbox.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/aegisbox"
    system "go", "build", *std_go_args(output: bin/"aegisbox-guest", ldflags: "-s -w"), "./cmd/aegisbox-guest"
  end

  test do
    assert_match "aegisbox version", shell_output("#{bin}/aegisbox version")
    system "#{bin}/aegisbox", "doctor"
  end
end
