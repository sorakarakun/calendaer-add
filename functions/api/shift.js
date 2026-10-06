export async function onRequestPost({ request, env }) {
  try {
    const { date, shiftType, note } = await request.json();

    if (!date || !shiftType) {
      return new Response(JSON.stringify({ error: '日付とシフト種別は必須です' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 1. Google サービスアカウント用のアクセストークンを取得
    const accessToken = await getGoogleAccessToken(
      env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
      env.GOOGLE_PRIVATE_KEY
    );

    // 2. シフトごとの開始・終了日時を設定
    let startDateTime, endDateTime;
    if (shiftType === '日勤') {
      startDateTime = `${date}T09:00:00+09:00`;
      endDateTime = `${date}T18:00:00+09:00`;
    } else if (shiftType === '夜勤') {
      startDateTime = `${date}T17:00:00+09:00`;
      // 翌日計算（簡易）
      const nextDay = new Date(new Date(date).getTime() + 24 * 60 * 60 * 1000)
        .toISOString()
        .split('T')[0];
      endDateTime = `${nextDay}T09:00:00+09:00`;
    } else {
      // 明け休み・公休などは終日イベント
      startDateTime = null;
    }

    const eventPayload = startDateTime
      ? {
          summary: `【シフト】${shiftType}`,
          description: note || '',
          start: { dateTime: startDateTime },
          end: { dateTime: endDateTime },
        }
      : {
          summary: `【シフト】${shiftType}`,
          description: note || '',
          start: { date: date },
          end: { date: date },
        };

    // 3. Google Calendar API へイベント作成リクエスト
    const calendarRes = await fetch(
      `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(env.GOOGLE_CALENDAR_ID)}/events`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(eventPayload),
      }
    );

    if (!calendarRes.ok) {
      const errDetail = await calendarRes.text();
      return new Response(JSON.stringify({ error: 'Calendar API Error', detail: errDetail }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// サービスアカウント秘密鍵からOAuth2アクセストークンを生成する補助関数
async function getGoogleAccessToken(clientEmail, privateKeyPem) {
  const cleanKey = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\\n/g, '')
    .replace(/\s+/g, '');

  const binaryDer = Uint8Array.from(atob(cleanKey), (c) => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    binaryDer.buffer,
    { name: 'RSASSA-PKPKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claimSet = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/calendar.events',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const base64UrlEncode = (obj) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const unsignedToken = `${base64UrlEncode(header)}.${base64UrlEncode(claimSet)}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const signedJwt = `${unsignedToken}.${btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedJwt,
    }),
  });

  const tokenData = await tokenRes.json();
  if (!tokenRes.ok) {
    throw new Error(`Google Auth Failed: ${tokenData.error_description || tokenData.error}`);
  }
  return tokenData.access_token;
}
