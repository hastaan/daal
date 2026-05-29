import daalFlatUrl from '@branding/sources/daal-eagle.svg?url';
import daalHeroUrl from '@branding/sources/daal-eagle-transparent.png';
import {
  PLATFORMS,
  RELEASE_VERSION,
  RELEASE_BASE_URL,
  RELEASE_PAGE_URL,
  REPO_URL,
  type Platform,
  type DownloadFile,
} from './downloads';

export function App() {
  return (
    <div>
      <header className="shell">
        <div className="nav">
          <div className="nav-brand">
            <img src={daalFlatUrl} alt="" aria-hidden />
            <span>Daal</span>
          </div>
          <nav className="nav-links">
            <a href="#downloads">Downloads</a>
            <a href={REPO_URL} rel="noopener noreferrer">
              Source
            </a>
            <a href={RELEASE_PAGE_URL} rel="noopener noreferrer">
              Releases
            </a>
          </nav>
        </div>
      </header>

      <main className="shell">
        <section className="hero">
          <div>
            <p className="tag">Anti-censorship client. Privacy first.</p>
            <h1>
              Reach the open web from <span className="accent">hostile networks</span>.
            </h1>
            <p className="lede">
              Daal is a small, fast, native client for desktop, Android and
              iOS. No analytics, no telemetry, no accounts. Bring your own
              subscription URL or share a config out of band — Daal handles
              the rest.
            </p>
          </div>
          <div className="hero-art">
            <img src={daalHeroUrl} alt="" aria-hidden />
          </div>
        </section>

        <section id="downloads" className="downloads-section">
          <div className="section-head">
            <h2>Downloads</h2>
            <span className="version">
              <strong>v{RELEASE_VERSION}</strong> · latest
            </span>
          </div>
          <p style={{ color: 'var(--muted)', fontSize: '14px', margin: '0 0 8px' }}>
            Pick your platform. Every binary is rebuilt from the tag on
            GitHub — verify the checksum if you cloned the repo.
          </p>

          <div className="platforms">
            {PLATFORMS.map((p) => (
              <PlatformCard key={p.id} platform={p} />
            ))}
          </div>

          <div className="verify-callout">
            <strong>Verify a download</strong>
            <div>SHA-256 sums for every artifact are on the release page.</div>
            <pre>{`sha256sum -c daal-v${RELEASE_VERSION}.sha256sum`}</pre>
          </div>
        </section>
      </main>

      <footer className="shell">
        <div className="foot">
          <div>
            Daal v{RELEASE_VERSION} · GPL-3.0-or-later · Built without telemetry.
          </div>
          <div style={{ display: 'flex', gap: '20px' }}>
            <a href={REPO_URL} rel="noopener noreferrer">
              GitHub
            </a>
            <a
              href={`${REPO_URL}/blob/main/README.md`}
              rel="noopener noreferrer"
            >
              README
            </a>
            <a
              href={`${REPO_URL}/blob/main/CHANGELOG.md`}
              rel="noopener noreferrer"
            >
              Changelog
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

function PlatformCard({ platform }: { platform: Platform }) {
  return (
    <article className="platform-card">
      <header className="platform-head">
        <div className="platform-icon" aria-hidden>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
            <path d={platform.iconPath} />
          </svg>
        </div>
        <div>
          <div className="platform-name">{platform.name}</div>
          <div className="platform-meta">{platform.meta}</div>
        </div>
      </header>

      <div className="download-list">
        {platform.files.map((f) => (
          <DownloadRow key={f.filename} file={f} />
        ))}
      </div>

      {platform.notes && <div className="notes">{platform.notes}</div>}
    </article>
  );
}

function DownloadRow({ file }: { file: DownloadFile }) {
  const href = `${RELEASE_BASE_URL}/${file.filename}`;
  if (file.unavailable) {
    return (
      <div className="download-item unavailable">
        <div>
          <div className="name">{file.filename}</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>{file.label}</div>
        </div>
        <span className="meta">building…</span>
      </div>
    );
  }
  return (
    <a
      className="download-item"
      href={href}
      // download attribute hints to browsers to save rather than open.
      download={file.filename}
      rel="noopener noreferrer"
    >
      <div>
        <div className="name">{file.filename}</div>
        <div style={{ color: 'var(--muted)', fontSize: 12 }}>{file.label}</div>
      </div>
      {file.size && <span className="meta">{file.size}</span>}
    </a>
  );
}
