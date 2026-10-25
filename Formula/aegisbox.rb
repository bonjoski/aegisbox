# typed: false
# frozen_string_literal: true

class Aegisbox < Formula
  desc "Unbreakable AI Execution Sandbox & Adversarial Range Engine"
  homepage "https://github.com/bonjoski/aegisbox"
  url "https://github.com/bonjoski/aegisbox/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "ad2d370e02bff999b346718bd64ac61057f8a1fd500f9e62471896f3fedd759d"
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
