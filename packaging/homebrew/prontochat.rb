class Prontochat < Formula
  desc "Terminal P2P encrypted messenger"
  homepage "https://github.com/mrloicbige-pro/ProntoChat"
  url "https://github.com/mrloicbige-pro/ProntoChat/archive/refs/tags/v0.1.0.tar.gz"
  version "0.1.0"

  depends_on "cmake" => :build
  depends_on "pkg-config" => :build
  depends_on "glib"
  depends_on "libnice"
  depends_on "libsodium"
  depends_on "libwebsockets"

  def install
    system "cmake", "-S", ".", "-B", "build",
                    "-DBUILD_TESTING=OFF",
                    *std_cmake_args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  service do
    run [opt_bin/"chatd"]
    keep_alive true
    log_path var/"log/prontochat-chatd.log"
    error_log_path var/"log/prontochat-chatd.log"
  end

  test do
    assert_match "Usage:", shell_output("#{bin}/chat 2>&1", 1)
  end
end
