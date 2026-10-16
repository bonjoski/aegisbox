# typed: false
# frozen_string_literal: true

class Aegisbox < Formula
  desc "Unbreakable AI Execution Sandbox & Adversarial Range Engine"
  homepage "https://github.com/bonjoski/aegisbox"
  url "https://github.com/bonjoski/aegisbox/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "533d399212b19b62a779f2703aa6ef480c67cf4e7aa65eb12a2d05328ed00146"
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
