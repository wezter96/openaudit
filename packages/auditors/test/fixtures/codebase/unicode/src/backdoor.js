app.get('/status', (req, res) => {
  const { timeout, ㅤ } = req.query;
  exec(['ping -c 1 google.com', ㅤ]);
});
