class Aws2Wrap < Formula
  include Language::Python::Virtualenv

  desc "Script to export current AWS SSO credentials or run a sub-process with them"
  homepage "https://github.com/linaro-its/aws2-wrap"
  url "https://files.pythonhosted.org/packages/fa/07/b0fbfc6d3640d0a55250b26900c534f655046bbbf081d111eab95c6611c7/aws2-wrap-1.2.8.tar.gz"
  sha256 "3e39be94c10e700a388fdc35da59a9232e766d65f05e57cd00651082a9887346"
  license "GPL-3.0-only"

  depends_on "python"

  resource "psutil" do
      url "https://files.pythonhosted.org/packages/d6/de/0999ea2562b96d7165812606b18f7169307b60cd378bc29cf3673322c7e9/psutil-5.9.1.tar.gz"
      sha256 "57f1819b5d9e95cdfb0c881a8a5b7d542ed0b7c522d575706a80bedc848c8954"
  end

  def install
      virtualenv_install_with_resources
  end
end