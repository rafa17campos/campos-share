export default function HomePage() {
  let hostname = 'AI Share';
  if (process.env.SHARE_BASE_URL) {
    try {
      hostname = new URL(process.env.SHARE_BASE_URL).hostname;
    } catch {
      hostname = process.env.SHARE_BASE_URL;
    }
  }

  return (
    <main
      style={{
        display: 'flex',
        minHeight: '100vh',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem',
        backgroundColor: '#f8fafc',
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
        color: '#0f172a',
        boxSizing: 'border-box',
      }}
    >
      <div
        style={{
          background: '#ffffff',
          border: '1px solid #e2e8f0',
          borderRadius: '0.75rem',
          padding: '2rem',
          maxWidth: '28rem',
          width: '100%',
          boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.05)',
          textAlign: 'center',
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.375rem',
            fontSize: '0.75rem',
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            color: '#64748b',
            background: '#f8fafc',
            border: '1px solid #e2e8f0',
            padding: '0.25rem 0.625rem',
            borderRadius: '9999px',
            marginBottom: '1rem',
          }}
        >
          <span
            style={{
              width: '0.5rem',
              height: '0.5rem',
              borderRadius: '50%',
              backgroundColor: '#2563eb',
            }}
          />
          Private Host
        </div>
        <h1
          style={{
            fontSize: '1.5rem',
            fontWeight: 700,
            margin: '0 0 0.75rem 0',
          }}
        >
          {hostname}
        </h1>
        <p
          style={{
            color: '#64748b',
            fontSize: '0.9375rem',
            lineHeight: 1.6,
            margin: 0,
          }}
        >
          Pages are unlisted. Anyone with a page URL can access it.
        </p>
      </div>
    </main>
  );
}
