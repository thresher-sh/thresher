# Homebrew Formula Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a custom Homebrew tap (`thresher-sh/homebrew-thresher`) so users can `brew install thresher`.

**Architecture:** A single formula file in a dedicated tap repo uses Homebrew's Python virtualenv support to install thresher and its pinned PyPI dependencies. Lima is declared as a recommended dependency.

**Tech Stack:** Ruby (Homebrew formula DSL), Python 3.13, Homebrew

**Spec:** `docs/superpowers/specs/2026-04-02-homebrew-formula-design.md`

---

## Chunk 1: Formula and Tap Repository

### Task 1: Create the Homebrew formula

**Files:**
- Create: `~/github/homebrew-thresher/Formula/thresher.rb`

- [ ] **Step 1: Create Formula directory**

```bash
mkdir -p ~/github/homebrew-thresher/Formula
```

- [ ] **Step 2: Write the formula**

Create `~/github/homebrew-thresher/Formula/thresher.rb`:

```ruby
class Thresher < Formula
  include Language::Python::Virtualenv

  desc "AI-powered supply chain security scanner for open source packages"
  homepage "https://github.com/thresher-sh/thresher"
  url "https://github.com/thresher-sh/thresher/archive/refs/tags/v1.0.0-alpha.tar.gz"
  sha256 "PLACEHOLDER_COMPUTE_AT_RELEASE"
  license "MIT"

  depends_on "python@3.13"
  depends_on "lima" => :recommended

  resource "click" do
    url "https://files.pythonhosted.org/packages/3d/fa/656b739db8587d7b5dfa22e22ed02566950fbfbcdc20311993483657a5c0/click-8.3.1.tar.gz"
    sha256 "12ff4785d337a1bb490bb7e9c2b1ee5da3112e94a8622f26a6c77f5d2fc6842a"
  end

  resource "jinja2" do
    url "https://files.pythonhosted.org/packages/df/bf/f7da0350254c0ed7c72f3e33cef02e048281fec7ecec5f032d4aac52226b/jinja2-3.1.6.tar.gz"
    sha256 "0137fb05990d35f1275a587e9aee6d56da821fc83491a0fb838183be43f66d6d"
  end

  resource "markupsafe" do
    url "https://files.pythonhosted.org/packages/7e/99/7690b6d4034fffd95959cbe0c02de8deb3098cc577c67bb6a24fe5d7caa7/markupsafe-3.0.3.tar.gz"
    sha256 "722695808f4b6457b320fdc131280796bdceb04ab50fe1795cd540799ebe1698"
  end

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz"
    sha256 "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"
  end

  def install
    virtualenv_install_with_resources
  end

  def caveats
    <<~EOS
      Lima is required to run thresher scans. If not already installed:
        brew install lima

      Before your first scan, provision the VM:
        thresher build
    EOS
  end

  test do
    assert_match "supply chain security scanner", shell_output("#{bin}/thresher --help")
  end
end
```

- [ ] **Step 3: Verify formula syntax**

```bash
cd ~/github/homebrew-thresher
brew audit --new Formula/thresher.rb
```

Expected: No errors (warnings about missing sha256 placeholder are OK since the release tarball doesn't exist yet).

### Task 2: Create tap README

**Files:**
- Create: `~/github/homebrew-thresher/README.md`

- [ ] **Step 1: Write README**

Create `~/github/homebrew-thresher/README.md`:

```markdown
# Homebrew Tap for Thresher

AI-powered supply chain security scanner for open source packages.

## Install

```bash
brew tap thresher-sh/thresher
brew install thresher
```

## Usage

```bash
# Build the scanner VM (first time only)
thresher build

# Scan a repository
thresher scan <repo_url>
```

## More Info

- [Thresher on GitHub](https://github.com/thresher-sh/thresher)
```

- [ ] **Step 2: Commit tap repo**

```bash
cd ~/github/homebrew-thresher
git init
git add .
git commit -m "Initial Homebrew formula for thresher"
```

### Task 3: Test local installation

- [ ] **Step 1: Compute tarball SHA (when release exists)**

Once the `v1.0.0-alpha` release is tagged and published on GitHub:

```bash
curl -sL https://github.com/thresher-sh/thresher/archive/refs/tags/v1.0.0-alpha.tar.gz | shasum -a 256
```

Update the `sha256` line in `Formula/thresher.rb` with the real hash.

- [ ] **Step 2: Test local tap install**

```bash
brew tap --force thresher-sh/thresher ~/github/homebrew-thresher
brew install thresher
```

- [ ] **Step 3: Verify installation**

```bash
thresher --help
# Should output: "Thresher — supply chain security scanner."

which thresher
# Should point to Homebrew's bin directory
```

- [ ] **Step 4: Run brew test**

```bash
brew test thresher
```

Expected: PASS

- [ ] **Step 5: Push tap repo to GitHub**

Create `thresher-sh/homebrew-thresher` on GitHub, then:

```bash
cd ~/github/homebrew-thresher
git remote add origin git@github.com:thresher-sh/homebrew-thresher.git
git push -u origin main
```

- [ ] **Step 6: Verify public install**

```bash
brew untap thresher-sh/thresher
brew tap thresher-sh/thresher
brew install thresher
thresher --help
```
