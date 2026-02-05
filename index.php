<?php
session_start();

// -------------------- CONFIG --------------------
const DB_PATH   = __DIR__ . '/data/app.db';
const CARDS_JSON = __DIR__ . '/cards.json';

$LEITNER_INTERVAL_DAYS = [1 => 0, 2 => 1, 3 => 3, 4 => 7];

function boxLabel(int $box): string {
  switch ($box) {
    case 1:
      return 'Again';
    case 2:
      return 'Hard';
    case 3:
      return 'Good';
    case 4:
    default:
      return 'Easy';
  }
}

const DEFAULT_NEW_PER_DAY = 20;
const DEFAULT_STRICT = 0;
const DEFAULT_SIM_THRESHOLD = 0.88;
const DEFAULT_SHOW_DEF_DE = 1;
const DEFAULT_SHOW_DEF_FA = 1;

// -------------------- UTIL --------------------
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function nowIso(): string { return (new DateTimeImmutable('now'))->format('c'); }
function todayKey(): string { return (new DateTimeImmutable('now'))->format('Y-m-d'); }

function ensureDataDir(): void {
  $dir = __DIR__ . '/data';
  if (!is_dir($dir)) { mkdir($dir, 0775, true); }
}
function db(): PDO {
  ensureDataDir();
  $pdo = new PDO('sqlite:' . DB_PATH);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $pdo->exec("PRAGMA journal_mode = WAL;");
  return $pdo;
}
function initDb(PDO $pdo): void {
  $pdo->exec("
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      email TEXT NULL,
      password_hash TEXT NULL,
      created_at TEXT NOT NULL,
      strict_grading INTEGER NOT NULL DEFAULT 0,
      new_per_day INTEGER NOT NULL DEFAULT 20,
      show_def_de INTEGER NOT NULL DEFAULT 1,
      show_def_fa INTEGER NOT NULL DEFAULT 1
    );
  ");
  foreach ([
    "ALTER TABLE users ADD COLUMN email TEXT NULL",
    "ALTER TABLE users ADD COLUMN password_hash TEXT NULL",
    "ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN strict_grading INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN new_per_day INTEGER NOT NULL DEFAULT 20",
    "ALTER TABLE users ADD COLUMN show_def_de INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE users ADD COLUMN show_def_fa INTEGER NOT NULL DEFAULT 1",
  ] as $sql) { try { $pdo->exec($sql); } catch (Throwable $e) {} }

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS progress (
      user_id INTEGER NOT NULL,
      card_id INTEGER NOT NULL,
      box INTEGER NOT NULL DEFAULT 1,
      learned INTEGER NOT NULL DEFAULT 0,
      introduced_at TEXT NULL,
      last_reviewed TEXT NULL,
      next_due TEXT NULL,
      correct_count INTEGER NOT NULL DEFAULT 0,
      wrong_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, card_id)
    );
  ");
  foreach ([ "ALTER TABLE progress ADD COLUMN introduced_at TEXT NULL" ] as $sql) { try { $pdo->exec($sql); } catch (Throwable $e) {} }

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS review_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ts TEXT NOT NULL,
      card_id INTEGER NOT NULL,
      correct INTEGER NOT NULL
    );
  ");
}

function getCards(): array {
  $json = file_get_contents(CARDS_JSON);
  $cards = json_decode($json, true);
  return is_array($cards) ? $cards : [];
}

// ---------- Normalization & grading ----------
function normalize_common(string $s): string {
  $s = trim(mb_strtolower($s));
  $s = preg_replace('/[^\p{L}\p{N}]+/u', ' ', $s);
  $s = preg_replace('/\s+/u', ' ', $s);
  return trim($s);
}
function normalize_german(string $s): string {
  $s = normalize_common($s);
  $s = str_replace(['ä','ö','ü','ß'], ['ae','oe','ue','ss'], $s);
  return $s;
}
function split_alternatives(string $s): array {
  $parts = preg_split('/\s*(?:\/|;|,|\bor\b|\band\b)\s*/i', $s);
  $out = [];
  foreach ($parts as $p) {
    $p = trim($p);
    if ($p !== '') $out[] = $p;
  }
  return array_values(array_unique($out));
}
function similarity(string $a, string $b): float {
  if ($a === '' || $b === '') return 0.0;
  $maxLen = max(mb_strlen($a), mb_strlen($b));
  if ($maxLen === 0) return 1.0;
  $dist = levenshtein($a, $b);
  return max(0.0, min(1.0, 1.0 - ($dist / $maxLen)));
}
function isCorrectAnswer(string $userAnswerRaw, string $expectedRaw, bool $isGerman, bool $strict, float $simThreshold): array {
  $user = $isGerman ? normalize_german($userAnswerRaw) : normalize_common($userAnswerRaw);
  $alts = split_alternatives($expectedRaw);
  if (count($alts) === 0) $alts = [$expectedRaw];

  $bestAlt = $alts[0];
  $bestScore = 0.0;

  foreach ($alts as $altRaw) {
    $alt = $isGerman ? normalize_german($altRaw) : normalize_common($altRaw);
    if ($user !== '' && $user === $alt) return [true, $altRaw, 1.0];

    if (!$strict) {
      if (mb_strlen($alt) >= 5 && (str_contains($alt, $user) || str_contains($user, $alt))) {
        return [true, $altRaw, 1.0];
      }
      $score = similarity($user, $alt);
      if ($score > $bestScore) { $bestScore = $score; $bestAlt = $altRaw; }
    }
  }

  if (!$strict && $bestScore >= $simThreshold) return [true, $bestAlt, $bestScore];
  return [false, $bestAlt, $bestScore];
}

// -------------------- AUTH --------------------
function currentUser(PDO $pdo): ?array {
  if (!isset($_SESSION['user_id'])) return null;
  $stmt = $pdo->prepare("SELECT id, name, strict_grading, new_per_day, show_def_de, show_def_fa FROM users WHERE id = :id");
  $stmt->execute([':id' => (int)$_SESSION['user_id']]);
  $u = $stmt->fetch(PDO::FETCH_ASSOC);
  return $u ?: null;
}
function login(PDO $pdo, string $name, string $password): bool {
  $name = trim($name);
  if ($name === '' || $password === '') return false;
  $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE name = :n");
  $stmt->execute([':n' => $name]);
  $u = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$u || !$u['password_hash']) return false;
  if (password_verify($password, (string)$u['password_hash'])) {
    $_SESSION['user_id'] = (int)$u['id'];
    return true;
  }
  return false;
}
function registerUser(PDO $pdo, string $name, string $email, string $password, string $captchaAnswer): array {
  $name = trim($name);
  $name = preg_replace('/[^a-zA-Z0-9_\- ]+/', '', $name) ?? '';
  if ($name === '') $name = 'user';
  $email = trim($email);
  if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    return [false, "Enter a valid email address."];
  }
  if (mb_strlen($password) < 6) return [false, "Password must be at least 6 characters."];
  $expected = (string)($_SESSION['captcha_expected'] ?? '');
  if ($expected === '' || trim($captchaAnswer) !== $expected) {
    return [false, "Captcha answer is incorrect."];
  }
  $hash = password_hash($password, PASSWORD_DEFAULT);
  try {
    $stmt = $pdo->prepare("
      INSERT INTO users(name, email, password_hash, created_at, strict_grading, new_per_day, show_def_de, show_def_fa)
      VALUES(:n, :e, :h, :c, :s, :npd, :sdd, :sdf)
    ");
    $stmt->execute([
      ':n'=>$name, ':e'=>$email, ':h'=>$hash, ':c'=>nowIso(),
      ':s'=>DEFAULT_STRICT, ':npd'=>DEFAULT_NEW_PER_DAY,
      ':sdd'=>DEFAULT_SHOW_DEF_DE, ':sdf'=>DEFAULT_SHOW_DEF_FA
    ]);
    $_SESSION['user_id'] = (int)$pdo->lastInsertId();
    return [true, "Registered and logged in."];
  } catch (Throwable $e) {
    return [false, "Username already exists. Try a different name."];
  }
}
function logout(): void { session_unset(); session_destroy(); }

// -------------------- PROGRESS --------------------
function ensureProgressRows(PDO $pdo, int $userId, array $cardIds): void {
  $pdo->beginTransaction();
  $stmt = $pdo->prepare("INSERT OR IGNORE INTO progress(user_id, card_id) VALUES(:u, :c)");
  foreach ($cardIds as $cid) { $stmt->execute([':u'=>$userId, ':c'=>$cid]); }
  $pdo->commit();
}
function getProgress(PDO $pdo, int $userId, int $cardId): ?array {
  $stmt = $pdo->prepare("SELECT * FROM progress WHERE user_id = :u AND card_id = :c");
  $stmt->execute([':u'=>$userId, ':c'=>$cardId]);
  $p = $stmt->fetch(PDO::FETCH_ASSOC);
  return $p ?: null;
}
function upsertProgress(PDO $pdo, int $userId, int $cardId, array $fields): void {
  $pdo->prepare("INSERT OR IGNORE INTO progress(user_id, card_id) VALUES(:u, :c)")->execute([':u'=>$userId, ':c'=>$cardId]);
  $sets=[]; $params=[':u'=>$userId, ':c'=>$cardId];
  foreach ($fields as $k=>$v) { $sets[]="$k = :$k"; $params[":$k"]=$v; }
  $sql="UPDATE progress SET ".implode(', ',$sets)." WHERE user_id = :u AND card_id = :c";
  $pdo->prepare($sql)->execute($params);
}
function logReview(PDO $pdo, int $userId, int $cardId, bool $correct): void {
  $stmt = $pdo->prepare("INSERT INTO review_log(user_id, ts, card_id, correct) VALUES(:u, :t, :c, :ok)");
  $stmt->execute([':u'=>$userId, ':t'=>nowIso(), ':c'=>$cardId, ':ok'=>($correct?1:0)]);
}
function nextDueForBox(array $intervals, int $box): string {
  $days = $intervals[$box] ?? 0;
  return (new DateTimeImmutable('now'))->modify('+'.$days.' days')->format('c');
}
function applyAnkiRating(PDO $pdo, int $userId, int $cardId, string $rating, array $intervals): void {
  $p = getProgress($pdo, $userId, $cardId);
  $box = $p ? (int)$p['box'] : 1;
  $box = min(4, max(1, $box));
  $currentLearned = $p ? (int)$p['learned'] : 0;
  $correctCount = $p ? (int)$p['correct_count'] : 0;
  $wrongCount = $p ? (int)$p['wrong_count'] : 0;

  switch ($rating) {
    case 'again':
      $box = 1;
      $learned = $currentLearned;
      $correct = false;
      $wrongCount++;
      break;
    case 'hard':
      $box = 2;
      $learned = 1;
      $correct = true;
      $correctCount++;
      break;
    case 'easy':
      $box = 4;
      $learned = 1;
      $correct = true;
      $correctCount++;
      break;
    case 'good':
    default:
      $box = 3;
      $learned = 1;
      $correct = true;
      $correctCount++;
      break;
  }

  $fields = [
    'box' => $box,
    'learned' => $learned,
    'last_reviewed' => nowIso(),
    'next_due' => nextDueForBox($intervals, $box),
    'correct_count' => $correctCount,
    'wrong_count' => $wrongCount,
  ];
  if (!$p || ($p['introduced_at'] ?? '') === '') $fields['introduced_at'] = nowIso();
  upsertProgress($pdo, $userId, $cardId, $fields);
  logReview($pdo, $userId, $cardId, $correct);
}
function stats(PDO $pdo, int $userId): array {
  $stmt = $pdo->prepare("
    SELECT
      COUNT(*) AS tracked,
      SUM(learned) AS learned,
      SUM(CASE WHEN next_due IS NULL OR next_due <= :now THEN 1 ELSE 0 END) AS due,
      SUM(CASE WHEN box=1 THEN 1 ELSE 0 END) AS b1,
      SUM(CASE WHEN box=2 THEN 1 ELSE 0 END) AS b2,
      SUM(CASE WHEN box=3 THEN 1 ELSE 0 END) AS b3,
      SUM(CASE WHEN box>=4 THEN 1 ELSE 0 END) AS b4
    FROM progress WHERE user_id = :u
  ");
  $stmt->execute([':u'=>$userId, ':now'=>nowIso()]);
  $r = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
  return array_map('intval', $r);
}
function dueCardIds(PDO $pdo, int $userId, ?int $boxFilter, int $limit): array {
  $boxClause = '';
  if ($boxFilter !== null) {
    $boxClause = ($boxFilter >= 4) ? "AND box >= :b " : "AND box = :b ";
  }
  $sql="SELECT card_id FROM progress WHERE user_id=:u ".$boxClause." AND (next_due IS NULL OR next_due <= :now)
        ORDER BY COALESCE(next_due,'1970-01-01T00:00:00Z') ASC, box ASC LIMIT :lim";
  $stmt=$pdo->prepare($sql);
  $stmt->bindValue(':u',$userId,PDO::PARAM_INT);
  if($boxFilter!==null) $stmt->bindValue(':b', min(4, max(1, $boxFilter)), PDO::PARAM_INT);
  $stmt->bindValue(':now',nowIso(),PDO::PARAM_STR);
  $stmt->bindValue(':lim',$limit,PDO::PARAM_INT);
  $stmt->execute();
  return array_map('intval',$stmt->fetchAll(PDO::FETCH_COLUMN,0));
}
function topicMastery(PDO $pdo, int $userId, array $cards): array {
  $by=[]; $cardById=[];
  foreach($cards as $c){ $cardById[(int)$c['id']]=$c; $t=(string)$c['topic']; if(!isset($by[$t]))$by[$t]=['total'=>0,'learned'=>0,'due'=>0,'newToday'=>0]; $by[$t]['total']++; }
  $stmt=$pdo->prepare("SELECT card_id, learned, next_due, introduced_at FROM progress WHERE user_id=:u");
  $stmt->execute([':u'=>$userId]);
  $rows=$stmt->fetchAll(PDO::FETCH_ASSOC);
  $now=new DateTimeImmutable('now'); $today=todayKey();
  foreach($rows as $r){
    $cid=(int)$r['card_id']; if(!isset($cardById[$cid])) continue;
    $t=(string)$cardById[$cid]['topic'];
    if((int)$r['learned']===1) $by[$t]['learned']++;
    $due=($r['next_due']===null || $r['next_due']==='' || (new DateTimeImmutable((string)$r['next_due']) <= $now));
    if($due) $by[$t]['due']++;
    if(($r['introduced_at'] ?? '')!==''){
      $d=(new DateTimeImmutable((string)$r['introduced_at']))->format('Y-m-d');
      if($d===$today) $by[$t]['newToday']++;
    }
  }
  ksort($by);
  return $by;
}
function streaks(PDO $pdo, int $userId): array {
  $stmt=$pdo->prepare("SELECT substr(ts,1,10) AS d FROM review_log WHERE user_id=:u GROUP BY d ORDER BY d ASC");
  $stmt->execute([':u'=>$userId]);
  $days=$stmt->fetchAll(PDO::FETCH_COLUMN,0);
  $set=[]; foreach($days as $d){ $set[(string)$d]=true; }
  $today=new DateTimeImmutable('now');
  $cur=0;
  for($i=0;$i<3650;$i++){
    $d=$today->modify("-$i days")->format('Y-m-d');
    if(isset($set[$d])) $cur++; else break;
  }
  $best=0; $run=0; $prev=null;
  foreach(array_keys($set) as $d){
    if($prev===null){ $run=1; $best=max($best,$run); $prev=$d; continue; }
    $prevDt=new DateTimeImmutable($prev);
    $dt=new DateTimeImmutable($d);
    $diff=(int)$prevDt->diff($dt)->format('%a');
    $run=($diff===1)?($run+1):1;
    $best=max($best,$run);
    $prev=$d;
  }
  return ['current'=>$cur,'best'=>$best];
}

function learnedSeries(PDO $pdo, int $userId, int $days): array {
  // Returns last N days: learned_new (cards first marked learned) and learned_cum
  $today = new DateTimeImmutable('now');
  $start = $today->modify('-'.($days-1).' days')->format('Y-m-d');
  $stmt = $pdo->prepare("
    SELECT substr(last_reviewed,1,10) AS d, COUNT(*) AS n
    FROM progress
    WHERE user_id=:u AND learned=1 AND last_reviewed IS NOT NULL AND substr(last_reviewed,1,10) >= :start
    GROUP BY d
  ");
  $stmt->execute([':u'=>$userId, ':start'=>$start]);
  $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
  $map = [];
  foreach($rows as $r){ $map[(string)$r['d']] = (int)$r['n']; }

  // cumulative learned up to each day (within window)
  $cum = 0;
  $out = [];
  for($i=$days-1; $i>=0; $i--){
    $d = $today->modify("-$i days")->format('Y-m-d');
    $n = $map[$d] ?? 0;
    $cum += $n;
    $out[] = ['d'=>$d, 'new'=>$n, 'cum'=>$cum];
  }
  return $out;
}

function accuracySeries(PDO $pdo, int $userId, int $days): array {
  $today = new DateTimeImmutable('now');
  $start = $today->modify('-'.($days-1).' days')->format('Y-m-d');
  $stmt=$pdo->prepare("
    SELECT substr(ts,1,10) AS d, COUNT(*) AS n, SUM(correct) AS ok
    FROM review_log
    WHERE user_id=:u AND substr(ts,1,10) >= :start
    GROUP BY d
  ");
  $stmt->execute([':u'=>$userId, ':start'=>$start]);
  $rows=$stmt->fetchAll(PDO::FETCH_ASSOC);
  $map=[];
  foreach($rows as $r){ $map[(string)$r['d']] = ['n'=>(int)$r['n'],'ok'=>(int)$r['ok']]; }

  $out=[];
  for($i=$days-1; $i>=0; $i--){
    $d=$today->modify("-$i days")->format('Y-m-d');
    $n=$map[$d]['n'] ?? 0;
    $ok=$map[$d]['ok'] ?? 0;
    $acc = $n>0 ? (100.0*$ok/$n) : null;
    $out[]=['d'=>$d,'n'=>$n,'acc'=>$acc];
  }
  return $out;
}

function svgLine(array $vals, int $w=900, int $h=220, int $pad=20): string {
  // $vals numeric list
  if(count($vals)===0) return '';
  $min = min($vals);
  $max = max($vals);
  if($max==$min) { $max = $min + 1; }
  $n = count($vals);
  $xstep = ($w - 2*$pad) / max(1, $n-1);
  $pts=[];
  for($i=0;$i<$n;$i++){
    $x = $pad + $i*$xstep;
    $y = $pad + ($h - 2*$pad) * (1 - (($vals[$i]-$min)/($max-$min)));
    $pts[] = round($x,2).",".round($y,2);
  }
  $poly = implode(" ", $pts);
  $svg = '<svg viewBox="0 0 '.$w.' '.$h.'" width="100%" height="'.$h.'" role="img" aria-label="progress chart">';
  $svg .= '<rect x="0" y="0" width="'.$w.'" height="'.$h.'" rx="14" fill="var(--card2)" stroke="var(--stroke)"/>';
  // grid lines
  for($g=0;$g<=4;$g++){
    $yy = $pad + ($h-2*$pad)*($g/4);
    $svg .= '<line x1="'.$pad.'" y1="'.$yy.'" x2="'.($w-$pad).'" y2="'.$yy.'" stroke="var(--stroke)" stroke-width="1"/>';
  }
  $svg .= '<polyline fill="none" stroke="var(--brand)" stroke-width="3" points="'.$poly.'"/>';
  // end dot
  $last = end($pts);
  if($last){
    [$lx,$ly] = explode(",",$last);
    $svg .= '<circle cx="'.$lx.'" cy="'.$ly.'" r="5" fill="var(--brand)"/>';
  }
  $svg .= '</svg>';
  return $svg;
}

function last30(PDO $pdo, int $userId): array {
  $today=new DateTimeImmutable('now');
  $start=$today->modify('-29 days')->format('Y-m-d');
  $stmt=$pdo->prepare("SELECT substr(ts,1,10) AS d, COUNT(*) AS n, SUM(correct) AS ok
                       FROM review_log WHERE user_id=:u AND substr(ts,1,10) >= :s GROUP BY d");
  $stmt->execute([':u'=>$userId,':s'=>$start]);
  $rows=$stmt->fetchAll(PDO::FETCH_ASSOC);
  $map=[]; foreach($rows as $r){ $map[(string)$r['d']]=['n'=>(int)$r['n'],'ok'=>(int)$r['ok']]; }
  $out=[];
  for($i=29;$i>=0;$i--){
    $d=$today->modify("-$i days")->format('Y-m-d');
    $n=$map[$d]['n'] ?? 0; $ok=$map[$d]['ok'] ?? 0;
    $acc=$n>0?round(100*$ok/$n):null;
    $out[]=['d'=>$d,'n'=>$n,'acc'=>$acc];
  }
  return $out;
}
function exportAll(PDO $pdo, int $userId): void {
  $p=$pdo->prepare("SELECT * FROM progress WHERE user_id=:u"); $p->execute([':u'=>$userId]); $progress=$p->fetchAll(PDO::FETCH_ASSOC);
  $s=$pdo->prepare("SELECT strict_grading, new_per_day, show_def_de, show_def_fa FROM users WHERE id=:u"); $s->execute([':u'=>$userId]); $settings=$s->fetch(PDO::FETCH_ASSOC) ?: [];
  $l=$pdo->prepare("SELECT ts, card_id, correct FROM review_log WHERE user_id=:u ORDER BY ts ASC"); $l->execute([':u'=>$userId]); $log=$l->fetchAll(PDO::FETCH_ASSOC);
  header('Content-Type: application/json');
  header('Content-Disposition: attachment; filename="leitner_backup.json"');
  echo json_encode(['exported_at'=>nowIso(),'settings'=>$settings,'progress'=>$progress,'review_log'=>$log], JSON_PRETTY_PRINT);
  exit;
}
function generateCaptcha(): array {
  $a = random_int(2, 9);
  $b = random_int(1, 9);
  $_SESSION['captcha_expected'] = (string)($a + $b);
  return ['question' => "What is $a + $b?"];
}
function importAll(PDO $pdo, int $userId, array $payload): array {
  if(!is_array($payload)) return [false,'Invalid JSON.'];
  $pdo->beginTransaction();
  try{
    if(isset($payload['settings']) && is_array($payload['settings'])){
      $sg=(int)($payload['settings']['strict_grading'] ?? DEFAULT_STRICT);
      $npd=(int)($payload['settings']['new_per_day'] ?? DEFAULT_NEW_PER_DAY);
      $sdd=(int)($payload['settings']['show_def_de'] ?? DEFAULT_SHOW_DEF_DE);
      $sdf=(int)($payload['settings']['show_def_fa'] ?? DEFAULT_SHOW_DEF_FA);
      $pdo->prepare("UPDATE users SET strict_grading=:s, new_per_day=:n, show_def_de=:sdd, show_def_fa=:sdf WHERE id=:u")
        ->execute([':s'=>$sg,':n'=>$npd,':sdd'=>$sdd,':sdf'=>$sdf,':u'=>$userId]);
    }
    if(isset($payload['progress']) && is_array($payload['progress'])){
      foreach($payload['progress'] as $r){
        if(!isset($r['card_id'])) continue;
        $cid=(int)$r['card_id'];
        upsertProgress($pdo,$userId,$cid,[
          'box'=>(int)($r['box'] ?? 1),
          'learned'=>(int)($r['learned'] ?? 0),
          'introduced_at'=>$r['introduced_at'] ?? null,
          'last_reviewed'=>$r['last_reviewed'] ?? null,
          'next_due'=>$r['next_due'] ?? null,
          'correct_count'=>(int)($r['correct_count'] ?? 0),
          'wrong_count'=>(int)($r['wrong_count'] ?? 0),
        ]);
      }
    }
    if(isset($payload['review_log']) && is_array($payload['review_log'])){
      $stmt=$pdo->prepare("INSERT INTO review_log(user_id, ts, card_id, correct) VALUES(:u,:t,:c,:ok)");
      foreach($payload['review_log'] as $r){
        if(!isset($r['ts'],$r['card_id'],$r['correct'])) continue;
        $stmt->execute([':u'=>$userId,':t'=>$r['ts'],':c'=>(int)$r['card_id'],':ok'=>(int)$r['correct']]);
      }
    }
    $pdo->commit();
    return [true,'Import complete.'];
  }catch(Throwable $e){
    $pdo->rollBack();
    return [false,'Import failed.'];
  }
}
function markIntroduced(PDO $pdo, int $userId, int $cardId): void {
  $p=getProgress($pdo,$userId,$cardId);
  if(!$p || ($p['introduced_at'] ?? '')===''){
    upsertProgress($pdo,$userId,$cardId,['introduced_at'=>nowIso()]);
  }
}

// -------------------- ROUTING --------------------
$pdo=db(); initDb($pdo);
$cards=getCards();
$cardById=[]; $topics=[];
foreach($cards as $c){ $cardById[(int)$c['id']]=$c; $topics[(string)$c['topic']]=true; }
$topics=array_keys($topics); sort($topics);

$page=$_GET['page'] ?? 'home';
$message='';

if($page==='logout'){ logout(); header('Location: ?page=login'); exit; }

if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='login'){
  if(login($pdo,(string)($_POST['name']??''),(string)($_POST['password']??''))){ header('Location: ?page=home'); exit; }
  $message='Login failed.';
}
if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='register'){
  [$ok,$msg]=registerUser(
    $pdo,
    (string)($_POST['name']??''),
    (string)($_POST['email']??''),
    (string)($_POST['password']??''),
    (string)($_POST['captcha_answer']??'')
  );
  $message=$msg;
  if($ok){ header('Location: ?page=home'); exit; }
}

$user=currentUser($pdo);
if(!$user && !in_array($page, ['login','register'], true)){ header('Location: ?page=login'); exit; }
if($user) ensureProgressRows($pdo,(int)$user['id'], array_keys($cardById));
$showDefDe=$user ? ((int)($user['show_def_de'] ?? DEFAULT_SHOW_DEF_DE)===1) : true;
$showDefFa=$user ? ((int)($user['show_def_fa'] ?? DEFAULT_SHOW_DEF_FA)===1) : true;

if($page==='export' && $user){ exportAll($pdo,(int)$user['id']); }
if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='import_all' && $user){
  if(!isset($_FILES['file']) || $_FILES['file']['error']!==UPLOAD_ERR_OK) $message='Upload failed.';
  else{
    $payload=json_decode(file_get_contents($_FILES['file']['tmp_name']),true);
    [$ok,$msg]=importAll($pdo,(int)$user['id'], is_array($payload)?$payload:[]);
    $message=$msg;
    $user=currentUser($pdo);
  }
}
if($_SERVER['REQUEST_METHOD']==='POST' && $page==='settings' && $user && ($_POST['action']??'')==='save_settings'){
  $strict=isset($_POST['strict_grading'])?1:0;
  $npd=max(1,min(50,(int)($_POST['new_per_day'] ?? DEFAULT_NEW_PER_DAY)));
  $showDefDe=isset($_POST['show_def_de'])?1:0;
  $showDefFa=isset($_POST['show_def_fa'])?1:0;
  $pdo->prepare("UPDATE users SET strict_grading=:s, new_per_day=:n, show_def_de=:sdd, show_def_fa=:sdf WHERE id=:u")
    ->execute([':s'=>$strict,':n'=>$npd,':sdd'=>$showDefDe,':sdf'=>$showDefFa,':u'=>(int)$user['id']]);
  $message='Settings saved.';
  $user=currentUser($pdo);
}
if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='anki_grade' && $user){
  $cardId = (int)($_POST['card_id'] ?? 0);
  $rating = (string)($_POST['rating'] ?? 'good');
  if($cardId > 0) applyAnkiRating($pdo, (int)$user['id'], $cardId, $rating, $LEITNER_INTERVAL_DAYS);
  $return = (string)($_POST['return'] ?? '?page=study');
  header('Location: '.$return);
  exit;
}
if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='grade' && $user){
  $cardId=(int)($_POST['card_id']??0);
  $dir=(string)($_POST['dir']??'de_en');
  $qmode=(string)($_POST['qmode']??'typed');
  $card=$cardById[$cardId]??null;
  $correct=false; $best=''; $score=0.0;

  if($card){
    if($qmode==='mcq'){
      $chosen=(string)($_POST['choice']??'');
      $expected=($dir==='en_de')?(string)$card['german']:(string)$card['english'];
      $isGerman=($dir==='en_de');
      $correct = ($isGerman?normalize_german($chosen):normalize_common($chosen)) === ($isGerman?normalize_german($expected):normalize_common($expected));
      $best=$expected;
    } else {
      $answer=(string)($_POST['answer']??'');
      $expected=($dir==='en_de')?(string)$card['german']:(string)$card['english'];
      $isGerman=($dir==='en_de');
      $strict=((int)$user['strict_grading']===1);
      [$correct,$best,$score]=isCorrectAnswer($answer,$expected,$isGerman,$strict,DEFAULT_SIM_THRESHOLD);
    }
  }
  $p=getProgress($pdo,(int)$user['id'],$cardId);
  $box=$p?(int)$p['box']:1;
  if($correct){
    $box=min(4,$box+1);
    $fields=['box'=>$box,'learned'=>1,'last_reviewed'=>nowIso(),
             'next_due'=>(new DateTimeImmutable('now'))->modify('+'.$LEITNER_INTERVAL_DAYS[$box].' days')->format('c'),
             'correct_count'=>($p?(int)$p['correct_count']:0)+1];
  } else {
    $box=1;
    $fields=['box'=>$box,'last_reviewed'=>nowIso(),
             'next_due'=>(new DateTimeImmutable('now'))->modify('+'.$LEITNER_INTERVAL_DAYS[$box].' days')->format('c'),
             'wrong_count'=>($p?(int)$p['wrong_count']:0)+1];
  }
  if(!$p || ($p['introduced_at'] ?? '')==='') $fields['introduced_at']=nowIso();
  upsertProgress($pdo,(int)$user['id'],$cardId,$fields);
  logReview($pdo,(int)$user['id'],$cardId,$correct);

  $return=(string)($_POST['return']??'?page=quiz');
  $sep=(strpos($return,'?')===false)?'?':'&';
  header('Location: '.$return.$sep.'graded=1&correct='.($correct?'1':'0').'&card='.$cardId.'&best='.urlencode($best));
  exit;
}

// -------------------- LAYOUT --------------------
function headerHtml(?array $user): void { ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leitner Trainer</title>


<style>
  :root{
    --bg0:#f5f7fb;
    --bg1:#e6eef9;
    --card:#ffffff;
    --card2:#f3f6fb;
    --stroke:#d7e1ef;
    --stroke2:#c5d3e6;
    --text:#162439;
    --muted:#4c5b72;
    --muted2:#6b7a90;
    --brand:#2b6cff;
    --brand2:#3d8bff;
    --ok:#1f9d63;
    --bad:#d6475a;
    --shadow:0 12px 28px rgba(22,36,57,.12);
    --radius:18px;
    --radius2:24px;
  }
  html[data-theme="dark"]{
    --bg0:#070a12;
    --bg1:#0b1220;
    --card:rgba(255,255,255,.06);
    --card2:rgba(255,255,255,.08);
    --stroke:rgba(255,255,255,.12);
    --stroke2:rgba(255,255,255,.18);
    --text:#eaf0ff;
    --muted:rgba(234,240,255,.75);
    --muted2:rgba(234,240,255,.55);
    --brand:#9ec1ff;
    --brand2:#6ea8ff;
    --ok:#7CFFB2;
    --bad:#ff8ea1;
    --shadow:0 10px 30px rgba(0,0,0,.35);
  }

  *{box-sizing:border-box}
  html,body{height:100%}
  body{
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
    margin:0;
    color:var(--text);
    background:
      radial-gradient(1200px 700px at 20% -10%, rgba(61,139,255,.18), transparent 60%),
      radial-gradient(1000px 600px at 90% 0%, rgba(31,157,99,.12), transparent 55%),
      linear-gradient(180deg, var(--bg0), var(--bg1) 35%, var(--bg1));
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    line-height:1.5;
  }
  html[data-theme="dark"] body{
    background:
      radial-gradient(1200px 700px at 20% -10%, rgba(110,168,255,.25), transparent 60%),
      radial-gradient(1000px 600px at 90% 0%, rgba(124,255,178,.14), transparent 55%),
      linear-gradient(180deg, var(--bg0), var(--bg1) 35%, var(--bg1));
  }

  a{color:var(--brand); text-decoration:none}
  a:hover{text-decoration:underline}
  a:focus-visible{outline:3px solid rgba(43,108,255,.35); outline-offset:2px; border-radius:8px}

  .wrap{max-width:1100px;margin:0 auto;padding:14px}
  @media(max-width:480px){ .wrap{padding:10px} }

  .topbar{
    position:sticky; top:0; z-index:50;
    backdrop-filter:saturate(140%) blur(10px);
    background:rgba(255,255,255,.85);
    border-bottom:1px solid var(--stroke);
  }
  html[data-theme="dark"] .topbar{
    background:rgba(7,10,18,.55);
  }
  .topbar-inner{max-width:1100px;margin:0 auto;padding:10px 14px}
  @media(max-width:480px){ .topbar-inner{padding:10px} }

  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .between{justify-content:space-between}

  .brandTitle{
    display:flex;align-items:center;gap:10px;
    font-weight:850; letter-spacing:.2px;
    font-size:20px;
  }
  .logoDot{
    width:12px;height:12px;border-radius:999px;
    background:linear-gradient(135deg, var(--brand2), rgba(31,157,99,.65));
    box-shadow:0 0 0 4px rgba(43,108,255,.12);
  }

  .badge{
    padding:7px 10px;
    border:1px solid var(--stroke);
    border-radius:999px;
    background:var(--card2);
    font-size:12px;
    color:var(--muted);
    white-space:nowrap;
  }

  .nav{
    display:flex;gap:8px;flex-wrap:wrap;align-items:center;
  }
  .nav a.badge{color:var(--text)}
  .nav a.badge:hover{background:rgba(43,108,255,.12); border-color:rgba(43,108,255,.25); text-decoration:none}

  /* Mobile nav */
  .navToggle{
    display:none;
    width:44px;height:44px;
    border-radius:14px;
    border:1px solid var(--stroke);
    background:var(--card2);
    color:var(--text);
    cursor:pointer;
  }
  .themeToggle{
    display:inline-flex; align-items:center; gap:8px;
    padding:8px 12px;
    border-radius:999px;
    border:1px solid var(--stroke);
    background:var(--card2);
    color:var(--text);
    font-size:12px;
    font-weight:700;
    cursor:pointer;
  }
  .themeToggle:hover{background:#ffffff}
  html[data-theme="dark"] .themeToggle:hover{background:rgba(255,255,255,.10)}
  .navMenu{
    display:flex;
  }
  @media(max-width:860px){
    .navToggle{display:inline-flex;align-items:center;justify-content:center}
    .navMenu{display:none; width:100%}
    .navMenu.open{display:flex}
    .nav{width:100%; padding-top:8px}
    .nav a.badge{flex:1; text-align:center; padding:10px 12px}
  }

  .card{
    background:linear-gradient(180deg, var(--card), var(--card2));
    border:1px solid var(--stroke);
    border-radius:var(--radius2);
    padding:14px;
    margin:12px 0;
    box-shadow: var(--shadow);
  }
  @media(max-width:480px){
    .card{padding:12px;border-radius:20px;margin:10px 0}
  }

  .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
  .col6{grid-column:span 6}
  .col12{grid-column:span 12}
  @media(max-width:900px){.col6{grid-column:span 12}}

  .btn{
    background:linear-gradient(135deg, rgba(43,108,255,.98), rgba(61,139,255,.95));
    border:1px solid rgba(43,108,255,.35);
    color:#ffffff;
    padding:12px 14px;
    border-radius:16px;
    cursor:pointer;
    font-weight:750;
    box-shadow:0 12px 22px rgba(43,108,255,.2);
  }
  .btn:hover{filter:brightness(1.02)}
  .btn:active{transform:translateY(1px)}
  .btn:focus-visible{outline:3px solid rgba(43,108,255,.35); outline-offset:2px}

  .btn2{
    background:var(--card2);
    border:1px solid var(--stroke);
    color:var(--text);
    padding:12px 14px;
    border-radius:16px;
    cursor:pointer;
    font-weight:650;
  }
  .btn2:hover{background:#ffffff}
  html[data-theme="dark"] .btn2:hover{background:rgba(255,255,255,.10)}
  .btn2:active{transform:translateY(1px)}
  .btn2:focus-visible{outline:3px solid rgba(43,108,255,.35); outline-offset:2px}

  .btn-anki{
    padding:10px 12px;
    border-radius:14px;
    border:1px solid var(--stroke);
    font-weight:700;
    cursor:pointer;
  }
  .anki-again{background:rgba(214,71,90,.12); color:var(--bad);}
  .anki-hard{background:rgba(248,205,126,.3); color:#8a5b00;}
  .anki-good{background:rgba(43,108,255,.12); color:var(--brand);}
  .anki-easy{background:rgba(31,157,99,.12); color:var(--ok);}

  input,select{
    width:100%;
    padding:12px 14px;
    border-radius:16px;
    border:1px solid var(--stroke);
    background:var(--card);
    color:var(--text);
    outline:none;
  }
  input::placeholder{color:var(--muted2)}
  input:focus,select:focus{
    border-color:rgba(43,108,255,.45);
    box-shadow:0 0 0 4px rgba(43,108,255,.14);
  }
  select{appearance:none; background-image: linear-gradient(45deg, transparent 50%, var(--muted) 50%), linear-gradient(135deg, var(--muted) 50%, transparent 50%);
    background-position: calc(100% - 18px) calc(1em + 2px), calc(100% - 13px) calc(1em + 2px);
    background-size: 5px 5px, 5px 5px;
    background-repeat: no-repeat;
  }

  .muted{color:var(--muted);font-size:13px;line-height:1.35}
  .mini{font-size:12px;color:var(--muted2)}
  .big{font-size:28px;font-weight:850;letter-spacing:.2px}
  .kpi{font-size:28px;font-weight:900;letter-spacing:.2px}
  @media(max-width:480px){ .big{font-size:24px} .kpi{font-size:26px} }

  .pill{
    display:inline-block;
    padding:7px 10px;
    border-radius:999px;
    background:rgba(43,108,255,.12);
    border:1px solid rgba(43,108,255,.25);
    font-size:12px;
    color:var(--text);
  }
  .hr{height:1px;background:var(--stroke);margin:14px 0}

  .ok{color:var(--ok)}
  .bad{color:var(--bad)}

  .bar{
    height:10px;
    background:rgba(43,108,255,.08);
    border-radius:999px;
    overflow:hidden;
    border:1px solid var(--stroke);
  }
  .bar>span{
    display:block;height:100%;
    background:linear-gradient(90deg, rgba(43,108,255,.75), rgba(31,157,99,.55));
  }

  details summary{list-style:none}
  details summary::-webkit-details-marker{display:none}

  /* Touch targets on mobile */
  @media(max-width:480px){
    .badge{padding:8px 11px}
    .btn,.btn2{width:100%; justify-content:center}
  }
</style>


</head>
<body>
<div class="topbar"><div class="topbar-inner">
    <div class="row between">
      <div class="row">
        <div class="brandTitle"><span class="logoDot"></span>Leitner Trainer</div>
        <?php if($user): ?>
          <div class="badge">User: <?=h((string)$user['name'])?></div>
          <div class="badge">Strict: <?=((int)$user['strict_grading']===1)?'ON':'OFF'?></div>
          <div class="badge">New/day: <?=h((string)$user['new_per_day'])?></div>
        <?php endif; ?>
      </div>
      <button class="themeToggle" type="button" onclick="toggleTheme()" aria-label="Toggle theme">
        <span id="themeIcon" aria-hidden="true">🌞</span>
        <span id="themeLabel">Light</span>
      </button>
      <?php if($user): ?>
      <button class="navToggle" type="button" onclick="toggleNav()">☰</button>
      <div id="navMenu" class="navMenu">
      <div class="nav">
        <a class="badge" href="?page=home">Home</a>
        <a class="badge" href="?page=dashboard">Dashboard</a>
        <a class="badge" href="?page=progress">Progress</a>
        <a class="badge" href="?page=study">Study</a>
        <a class="badge" href="?page=quiz">Quiz</a>
        <a class="badge" href="?page=learned">Learned</a>
        <a class="badge" href="?page=backup">Backup</a>
        <a class="badge" href="?page=settings">Settings</a>
        <a class="badge" href="?page=logout">Logout</a>
      </div>
      </div>
      </div>
      <?php endif; ?>
    </div>
  </div>
  </div></div>
<div class="wrap">
<?php }
function footerHtml(): void { ?>
  <div class="card muted">Tip: Set your "New/day" pacing in Settings, then do due reviews daily. 🔊 uses browser TTS.</div>
</div>
<script>
function toggle(id){ const el=document.getElementById(id); if(!el) return; el.style.display=(el.style.display==='none'||!el.style.display)?'block':'none'; }
function toggleNav(){
  const m=document.getElementById('navMenu');
  if(!m) return;
  m.classList.toggle('open');
}
function applyTheme(theme){
  document.documentElement.setAttribute('data-theme', theme);
  const icon = document.getElementById('themeIcon');
  const label = document.getElementById('themeLabel');
  if (icon) icon.textContent = theme === 'dark' ? '🌙' : '🌞';
  if (label) label.textContent = theme === 'dark' ? 'Dark' : 'Light';
}
function toggleTheme(){
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', next);
  applyTheme(next);
}
const savedTheme = localStorage.getItem('theme') || 'light';
applyTheme(savedTheme);
function speak(text, lang){
  if(!('speechSynthesis' in window)) { alert('Speech not supported in this browser.'); return; }
  const u = new SpeechSynthesisUtterance(text); u.lang = lang;
  window.speechSynthesis.cancel(); window.speechSynthesis.speak(u);
}
</script>
</body></html>
<?php }

headerHtml($user);

// -------------------- PAGES --------------------
if($page==='login'){ ?>
  <div class="card">
    <h2>Login</h2>
    <?php if($message): ?><div class="badge"><?=h($message)?></div><?php endif; ?>
    <div class="card" style="margin-top:10px">
      <h3>Sign in</h3>
      <form method="post">
        <input type="hidden" name="action" value="login">
        <label class="muted">Username</label>
        <input name="name" required>
        <div style="height:10px"></div>
        <label class="muted">Password</label>
        <input type="password" name="password" required>
        <div style="height:12px"></div>
        <button class="btn" type="submit">Login</button>
      </form>
      <div class="hr"></div>
      <div class="muted">New here? <a href="?page=register">Create an account</a>.</div>
    </div>
  </div>
<?php footerHtml(); exit; }

if($page==='register'){ ?>
  <div class="card">
    <h2>Create account</h2>
    <?php if($message): ?><div class="badge"><?=h($message)?></div><?php endif; ?>
    <div class="card" style="margin-top:10px">
      <form method="post">
        <?php $captcha = generateCaptcha(); ?>
        <input type="hidden" name="action" value="register">
        <label class="muted">Username</label>
        <input name="name" required>
        <div style="height:10px"></div>
        <label class="muted">Email</label>
        <input type="email" name="email" autocomplete="email" required>
        <div style="height:10px"></div>
        <label class="muted">Password (min 6 chars)</label>
        <input type="password" name="password" required>
        <div style="height:12px"></div>
        <label class="muted">Captcha: <?=h($captcha['question'])?></label>
        <input name="captcha_answer" inputmode="numeric" autocomplete="off" required>
        <div style="height:12px"></div>
        <button class="btn2" type="submit">Register</button>
      </form>
      <div class="hr"></div>
      <div class="muted">Already have an account? <a href="?page=login">Sign in</a>.</div>
    </div>
  </div>
<?php footerHtml(); exit; }

if($page==='home'){
  $s=stats($pdo,(int)$user['id']); $st=streaks($pdo,(int)$user['id']); ?>
  <?php if($message): ?><div class="card"><div class="badge"><?=h($message)?></div></div><?php endif; ?>
  <div class="grid">
    <div class="card col6">
      <div class="pill">Due now</div>
      <div class="kpi"><?=h((string)$s['due'])?></div>
      <div class="muted">Cards ready for Leitner review</div>
      <div class="hr"></div>
      <div class="row">
        <a class="btn" href="?page=study&mode=due">Study due</a>
        <a class="btn2" href="?page=quiz&mode=due">Quiz due</a>
      </div>
    </div>
    <div class="card col6">
      <div class="pill">Streaks</div>
      <div class="row" style="margin-top:8px">
        <span class="badge">Current: <?=h((string)$st['current'])?> days</span>
        <span class="badge">Best: <?=h((string)$st['best'])?> days</span>
      </div>
      <div class="hr"></div>
      <div class="muted">Anki boxes:</div>
      <div class="row" style="margin-top:8px">
        <span class="badge"><?=h(boxLabel(1))?> <?=h((string)$s['b1'])?></span>
        <span class="badge"><?=h(boxLabel(2))?> <?=h((string)$s['b2'])?></span>
        <span class="badge"><?=h(boxLabel(3))?> <?=h((string)$s['b3'])?></span>
        <span class="badge"><?=h(boxLabel(4))?> <?=h((string)$s['b4'])?></span>
      </div>
      <div class="hr"></div>
      <span class="badge">Learned: <?=h((string)$s['learned'])?></span>
    </div>
  </div>
  </div></div>
<div class="wrap">
<?php }

if($page==='dashboard'){
  $mastery=topicMastery($pdo,(int)$user['id'],$cards);
  $series=last30($pdo,(int)$user['id']); ?>
  <div class="card">
    <h2>Dashboard — Mastery by Topic</h2>
    <div class="muted">New today = introduced cards today (pacing).</div>
    <?php foreach($mastery as $t=>$m):
      $pct=$m['total']>0?round(100*$m['learned']/$m['total']):0; ?>
      <div class="card" style="margin:10px 0">
        <div class="row between">
          <div class="row"><span class="pill"><?=h($t)?></span><span class="badge"><?=h((string)$pct)?>% learned</span></div>
          <div class="row">
            <a class="badge" href="?page=study&mode=topic&topic=<?=urlencode($t)?>">Study</a>
            <a class="badge" href="?page=quiz&mode=topic&topic=<?=urlencode($t)?>">Quiz</a>
          </div>
        </div>
        <div class="hr"></div>
        <div class="bar"><span style="width:<?=h((string)$pct)?>%"></span></div>
        <div class="row" style="margin-top:8px">
          <span class="badge">Total <?=h((string)$m['total'])?></span>
          <span class="badge">Learned <?=h((string)$m['learned'])?></span>
          <span class="badge">Due <?=h((string)$m['due'])?></span>
          <span class="badge">New today <?=h((string)$m['newToday'])?></span>
        </div>
      </div>
    <?php endforeach; ?>
  </div>

  <div class="card">
    <h2>Last 30 days — Activity & Accuracy</h2>
    <div class="muted">Bars = number of reviews. Labels = accuracy % when available.</div>
    <div class="hr"></div>
    <div style="display:flex;gap:6px;align-items:end;overflow-x:auto;padding-bottom:8px">
      <?php $maxN=1; foreach($series as $pt){ $maxN=max($maxN,(int)$pt['n']); }
      foreach($series as $pt):
        $hgt=(int)round(80*((int)$pt['n']/$maxN));
        $acc=$pt['acc']; ?>
        <div style="min-width:18px;text-align:center">
          <div title="<?=h($pt['d'])?>: <?=h((string)$pt['n'])?> reviews" style="height:<?=h((string)$hgt)?>px;background:rgba(158,193,255,.65);border-radius:6px"></div>
          <div class="mini muted" style="margin-top:4px"><?= $acc===null ? '' : h((string)$acc) ?></div>
        </div>
      <?php endforeach; ?>
    </div>
  </div>
  </div></div>
<div class="wrap">
<?php }

if($page==='settings'){ ?>
  <div class="card">
    <h2>Settings</h2>
    <?php if($message): ?><div class="badge"><?=h($message)?></div><?php endif; ?>
    <form method="post" class="grid">
      <input type="hidden" name="action" value="save_settings">
      <div class="col6">
        <label class="muted">New cards per day</label>
        <input type="number" name="new_per_day" min="1" max="50" value="<?=h((string)$user['new_per_day'])?>">
      </div>
      <div class="col6">
        <label class="muted">Strict grading</label>
        <div class="row" style="margin-top:8px">
          <label class="badge"><input type="checkbox" name="strict_grading" <?=((int)$user['strict_grading']===1)?'checked':''?>> ON</label>
          <span class="muted mini">Lenient accepts small typos & umlaut variants.</span>
        </div>
      </div>
      <div class="col12">
        <label class="muted">Definition display</label>
        <div class="row" style="margin-top:8px;gap:10px;flex-wrap:wrap">
          <label class="badge"><input type="checkbox" name="show_def_de" <?=((int)($user['show_def_de'] ?? DEFAULT_SHOW_DEF_DE)===1)?'checked':''?>> German</label>
          <label class="badge"><input type="checkbox" name="show_def_fa" <?=((int)($user['show_def_fa'] ?? DEFAULT_SHOW_DEF_FA)===1)?'checked':''?>> Persian</label>
        </div>
      </div>
      <div class="col12"><button class="btn" type="submit">Save</button></div>
    </form>
  </div>
  </div></div>
<div class="wrap">
<?php }

if($page==='backup'){ ?>
  <div class="card">
    <h2>Backup</h2>
    <?php if($message): ?><div class="badge"><?=h($message)?></div><?php endif; ?>
    <div class="hr"></div>
    <div class="row"><a class="btn" href="?page=export">Export backup JSON</a></div>
    <div class="hr"></div>
    <h3>Import</h3>
    <form method="post" enctype="multipart/form-data" class="grid">
      <input type="hidden" name="action" value="import_all">
      <div class="col6"><label class="muted">Select backup JSON</label><input type="file" name="file" accept="application/json" required></div>
      <div class="col6" style="display:flex;align-items:end"><button class="btn2" type="submit">Import</button></div>
    </form>
  </div>
  </div></div>
<div class="wrap">
<?php }

if($page==='learned'){
  $q=isset($_GET['q'])?trim((string)$_GET['q']):'';
  $topic=isset($_GET['topic'])&&$_GET['topic']!==''?(string)$_GET['topic']:null;
  $boxFilter=isset($_GET['box'])&&$_GET['box']!==''?(int)$_GET['box']:null;
  $limit=isset($_GET['limit'])?max(10,min(200,(int)$_GET['limit'])):50;

  $conds=["user_id=:u","learned=1"];
  $stmt=$pdo->prepare("SELECT card_id, box, correct_count, wrong_count FROM progress WHERE user_id=:u AND learned=1 ORDER BY box DESC, correct_count DESC LIMIT :lim");
  $stmt->bindValue(':u',(int)$user['id'],PDO::PARAM_INT);
  $stmt->bindValue(':lim',$limit,PDO::PARAM_INT);
  $stmt->execute();
  $rows=$stmt->fetchAll(PDO::FETCH_ASSOC);
  $items=[];
  foreach($rows as $r){
    if($boxFilter!==null){
      $boxValue = (int)$r['box'];
      if ($boxFilter >= 4) {
        if ($boxValue < 4) continue;
      } elseif ($boxValue !== $boxFilter) {
        continue;
      }
    }
    $cid=(int)$r['card_id']; if(!isset($cardById[$cid])) continue;
    $c=$cardById[$cid];
    if($topic!==null && $c['topic']!==$topic) continue;
    if($q!==''){
      $hay=normalize_common($c['german'].' '.$c['english'].' '.$c['definition'].' '.($c['meaning_fa'] ?? ''));
      if(!str_contains($hay, normalize_common($q))) continue;
    }
    $items[]=['c'=>$c,'p'=>$r];
  }
?>
  <div class="card">
    <h2>Learned words</h2>
    <form method="get" class="grid">
      <input type="hidden" name="page" value="learned">
      <div class="col6"><label class="muted">Search</label><input name="q" value="<?=h($q)?>"></div>
      <div class="col6"><label class="muted">Topic</label>
        <select name="topic"><option value="">All</option>
          <?php foreach($topics as $t): ?><option value="<?=h($t)?>" <?=($topic===$t)?'selected':''?>><?=h($t)?></option><?php endforeach; ?>
        </select>
      </div>
      <div class="col6"><label class="muted">Anki box</label>
        <select name="box"><option value="">All</option>
          <?php for($b=1;$b<=4;$b++): ?><option value="<?=$b?>" <?=($boxFilter===$b)?'selected':''?>><?=h(boxLabel($b))?></option><?php endfor; ?>
        </select>
      </div>
      <div class="col6"><label class="muted">Max results</label><input type="number" name="limit" min="10" max="200" value="<?=h((string)$limit)?>"></div>
      <div class="col12"><button class="btn" type="submit">Apply</button></div>
    </form>
  </div>
  <?php foreach($items as $it): $c=$it['c']; $p=$it['p']; ?>
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div class="row"><span class="pill"><?=h($c['topic'])?></span><span class="badge"><?=h(boxLabel(min(4, max(1, (int)$p['box']))))?></span></div>
        <div class="row">
          <button class="btn2" type="button" onclick="speak('<?=h(addslashes($c['german']))?>','de-DE')">🔊 DE</button>
          <button class="btn2" type="button" onclick="speak('<?=h(addslashes($c['english']))?>','en-US')">🔊 EN</button>
          <a class="badge" href="?page=quiz&single=1&card=<?=h((string)$c['id'])?>">Quiz</a>
        </div>
      </div>
      <div class="big" style="margin-top:10px"><?=h($c['german'])?></div>
      <div><b>English:</b> <?=h($c['english'])?></div>
      <?php if($showDefDe): ?><div class="muted" style="margin-top:6px"><b>DE:</b> <?=h($c['definition'])?></div><?php endif; ?>
      <?php if($showDefFa): ?><div class="muted" style="margin-top:6px"><b>Meaning (FA):</b> <?=h((string)($c['meaning_fa'] ?? ''))?></div><?php endif; ?>
      <details style="margin-top:10px"><summary class="badge" style="cursor:pointer;display:inline-block">Example</summary>
        <div class="muted" style="margin-top:8px"><?=h($c['sentence'])?></div>
      </details>
      <div class="hr"></div>
      <div class="muted mini">Correct: <?=h((string)$p['correct_count'])?> · Wrong: <?=h((string)$p['wrong_count'])?></div>
    </div>
  <?php endforeach; ?>
<?php }

if($page==='study'){
  $mode=$_GET['mode'] ?? 'topic';
  $topic=isset($_GET['topic'])&&$_GET['topic']!==''?(string)$_GET['topic']:null;
  $boxFilter=isset($_GET['box'])&&$_GET['box']!==''?(int)$_GET['box']:null;
  $limit=isset($_GET['limit'])?max(5,min(50,(int)$_GET['limit'])):20;
  $selected=[];

  if($mode==='due'){
    $due=dueCardIds($pdo,(int)$user['id'],$boxFilter,$limit);
    foreach($due as $cid){ $c=$cardById[$cid]??null; if($c && ($topic===null || $c['topic']===$topic)) $selected[]=$c; }
  } else {
    $today=todayKey(); $npd=(int)$user['new_per_day'];
    $stmt=$pdo->prepare("SELECT COUNT(*) FROM progress WHERE user_id=:u AND introduced_at IS NOT NULL AND substr(introduced_at,1,10)=:d");
    $stmt->execute([':u'=>(int)$user['id'],':d'=>$today]);
    $introducedToday=(int)$stmt->fetchColumn();
    $remaining=max(0,$npd-$introducedToday);

    foreach($cards as $c){
      if($topic!==null && $c['topic']!==$topic) continue;
      $p=getProgress($pdo,(int)$user['id'],(int)$c['id']);
      if(!$p || ($p['introduced_at'] ?? '')==='') $selected[]=$c;
    }
    $selected=array_slice($selected,0, min($limit, $remaining>0?$remaining:$limit));
  }
?>
  <div class="card">
    <h2>Study</h2>
    <form method="get" class="grid">
      <input type="hidden" name="page" value="study">
      <div class="col6"><label class="muted">Mode</label>
        <select name="mode">
          <option value="topic" <?=$mode==='topic'?'selected':''?>>Topic (new, paced)</option>
          <option value="due" <?=$mode==='due'?'selected':''?>>Due reviews</option>
        </select>
      </div>
      <div class="col6"><label class="muted">Topic</label>
        <select name="topic"><option value="">All</option>
          <?php foreach($topics as $t): ?><option value="<?=h($t)?>" <?=($topic===$t)?'selected':''?>><?=h($t)?></option><?php endforeach; ?>
        </select>
      </div>
      <div class="col6"><label class="muted">Anki box filter (due)</label>
        <select name="box"><option value="">All</option>
          <?php for($b=1;$b<=4;$b++): ?><option value="<?=$b?>" <?=($boxFilter===$b)?'selected':''?>><?=h(boxLabel($b))?></option><?php endfor; ?>
        </select>
      </div>
      <div class="col6"><label class="muted">Cards to show</label><input type="number" name="limit" min="5" max="50" value="<?=h((string)$limit)?>"></div>
      <div class="col12"><button class="btn" type="submit">Load</button></div>
    </form>
    <?php if($mode==='topic'): ?><div class="muted mini" style="margin-top:10px">Pacing: limited by your New/day setting.</div><?php endif; ?>
  </div>

  <?php foreach($selected as $c):
    $cid=(int)$c['id']; markIntroduced($pdo,(int)$user['id'],$cid);
    $p=getProgress($pdo,(int)$user['id'],$cid); $box=$p?(int)$p['box']:1; $ansId="ans_$cid"; ?>
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div class="row"><span class="pill"><?=h($c['topic'])?></span><span class="badge">Card #<?=$cid?></span><span class="badge"><?=h(boxLabel(min(4, max(1, $box))))?></span></div>
        <div class="row">
          <button class="btn2" type="button" onclick="speak('<?=h(addslashes($c['german']))?>','de-DE')">🔊 DE</button>
          <button class="btn2" type="button" onclick="speak('<?=h(addslashes($c['english']))?>','en-US')">🔊 EN</button>
          <a class="badge" href="?page=quiz&single=1&card=<?=$cid?>">Quiz</a>
        </div>
      </div>
      <div class="big" style="margin-top:10px"><?=h($c['german'])?></div>
      <div class="hr"></div>
      <button class="btn2" type="button" onclick="toggle('<?=h($ansId)?>')">Show / hide answer</button>
      <div id="<?=h($ansId)?>" style="display:none;margin-top:12px">
        <div><b>English:</b> <?=h($c['english'])?></div>
        <?php if($showDefDe): ?><div style="margin-top:8px"><b>Definition (DE):</b> <?=h($c['definition'])?></div><?php endif; ?>
        <?php if($showDefFa): ?><div style="margin-top:8px"><b>Meaning (FA):</b> <?=h((string)($c['meaning_fa'] ?? ''))?></div><?php endif; ?>
        <div style="margin-top:8px"><b>Example:</b> <?=h($c['sentence'])?></div>
        <div class="hr"></div>
        <div class="muted mini">Anki-style review</div>
        <form method="post" class="row" style="margin-top:8px">
          <input type="hidden" name="action" value="anki_grade">
          <input type="hidden" name="card_id" value="<?=h((string)$cid)?>">
          <input type="hidden" name="return" value="<?=h($_SERVER['REQUEST_URI'])?>">
          <button class="btn-anki anki-again" type="submit" name="rating" value="again">Again</button>
          <button class="btn-anki anki-hard" type="submit" name="rating" value="hard">Hard</button>
          <button class="btn-anki anki-good" type="submit" name="rating" value="good">Good</button>
          <button class="btn-anki anki-easy" type="submit" name="rating" value="easy">Easy</button>
        </form>
      </div>
    </div>
  <?php endforeach; ?>
<?php }

if($page==='quiz'){
  $dir=$_GET['dir'] ?? 'de_en';
  $mode=$_GET['mode'] ?? 'due';
  $qmode=$_GET['qmode'] ?? 'typed';
  $single=isset($_GET['single'])?(int)$_GET['single']:0;
  $topic=isset($_GET['topic'])&&$_GET['topic']!==''?(string)$_GET['topic']:null;
  $boxFilter=isset($_GET['box'])&&$_GET['box']!==''?(int)$_GET['box']:null;
  $limit=isset($_GET['limit'])?max(5,min(50,(int)$_GET['limit'])):20;

  $candidateIds=[];
  if($single===1 && isset($_GET['card'])) $candidateIds=[(int)$_GET['card']];
  elseif($mode==='due'){
    $candidateIds=dueCardIds($pdo,(int)$user['id'],$boxFilter,$limit);
    if($topic!==null) $candidateIds=array_values(array_filter($candidateIds, fn($id)=>isset($cardById[$id]) && $cardById[$id]['topic']===$topic));
  } else {
    foreach($cards as $c){ if($topic===null || $c['topic']===$topic) $candidateIds[]=(int)$c['id']; }
    shuffle($candidateIds); $candidateIds=array_slice($candidateIds,0,$limit);
  }

  $cardId=$candidateIds[0] ?? null;
  $card=$cardId?($cardById[(int)$cardId]??null):null;

  $graded=($_GET['graded'] ?? '')==='1';
  $correct=($_GET['correct'] ?? '')==='1';
  $gradedCardId=isset($_GET['card'])?(int)$_GET['card']:null;
  $best=isset($_GET['best'])?(string)$_GET['best']:'';

  if($graded): ?>
    <div class="card">
      <?php if($correct): ?><div class="big ok">✅ Correct</div><?php else: ?><div class="big bad">❌ Not quite</div><?php endif; ?>
      <?php if($gradedCardId && isset($cardById[$gradedCardId])):
        $gc=$cardById[$gradedCardId]; ?>
        <div class="hr"></div>
        <div><b>German:</b> <?=h($gc['german'])?></div>
        <div><b>English:</b> <?=h($gc['english'])?></div>
        <?php if(!$correct && $best!==''): ?><div class="muted">Expected: <b><?=h($best)?></b></div><?php endif; ?>
      <?php endif; ?>
      <div class="hr"></div>
      <a class="btn" href="<?=h(strtok($_SERVER["REQUEST_URI"], '&'))?>">Next</a>
    </div>
  <?php endif;

  if(!$card): ?>
    <div class="card"><div class="muted">No cards available.</div></div>
  <?php else:
    $prompt=($dir==='en_de')?(string)$card['english']:(string)$card['german'];
	    $correctAns=($dir==='en_de')?(string)$card['german']:(string)$card['english'];

    $options=[];
    if($qmode==='mcq'){
      $pool=[];
      foreach($cards as $c){
        if($topic!==null && $c['topic']!==$topic) continue;
        $pool[] = ($dir==='en_de')?(string)$c['german']:(string)$c['english'];
      }
      $pool=array_values(array_unique(array_filter($pool, fn($x)=>normalize_common($x)!==normalize_common($correctAns))));
      shuffle($pool);
      $options=array_slice($pool,0,3); $options[]=$correctAns; shuffle($options);
    }
  ?>
    <div class="card">
      <h2>Quiz</h2>
      <div class="row" style="justify-content:space-between">
        <div class="row"><span class="pill"><?=h($card['topic'])?></span><span class="badge">Mode <?=h(strtoupper($qmode))?></span></div>
        <button class="btn2" type="button" onclick="speak('<?=h(addslashes($prompt))?>','<?=($dir==='en_de')?'en-US':'de-DE'?>')">🔊 Speak</button>
      </div>
      <div class="big" style="margin-top:10px"><?=h($prompt)?></div>

      <details style="margin-top:10px"><summary class="badge" style="cursor:pointer;display:inline-block">Hint</summary>
        <?php if($showDefDe): ?><div class="muted" style="margin-top:8px"><b>DE:</b> <?=h($card['definition'])?></div><?php endif; ?>
        <?php if($showDefFa): ?><div class="muted" style="margin-top:8px"><b>Meaning (FA):</b> <?=h((string)($card['meaning_fa'] ?? ''))?></div><?php endif; ?>
        <div class="muted" style="margin-top:8px"><?=h($card['sentence'])?></div>
      </details>

      <div class="hr"></div>
      <form method="post" class="grid">
        <input type="hidden" name="action" value="grade">
        <input type="hidden" name="card_id" value="<?=h((string)$card['id'])?>">
        <input type="hidden" name="dir" value="<?=h($dir)?>">
        <input type="hidden" name="qmode" value="<?=h($qmode)?>">
        <input type="hidden" name="return" value="<?=h($_SERVER['REQUEST_URI'])?>">

        <?php if($qmode==='mcq'): ?>
          <div class="col12">
            <label class="muted">Choose one</label>
            <div class="grid">
              <?php foreach($options as $opt): ?>
                <div class="col6">
                  <label class="badge" style="display:block;cursor:pointer">
                    <input type="radio" name="choice" value="<?=h($opt)?>" required> <?=h($opt)?>
                  </label>
                </div>
              <?php endforeach; ?>
            </div>
          </div>
        <?php else: ?>
          <div class="col12">
            <label class="muted">Your answer</label>
            <input name="answer" autocomplete="off" autofocus>
          </div>
        <?php endif; ?>

        <div class="col12 row" style="margin-top:10px">
          <button class="btn" type="submit">Check</button>
          <a class="btn2" href="?page=study&mode=topic&topic=<?=urlencode((string)$card['topic'])?>">Study topic</a>
        </div>
      </form>

      <div class="hr"></div>
      <form method="get" class="grid">
        <input type="hidden" name="page" value="quiz">
        <div class="col6"><label class="muted">Source</label>
          <select name="mode"><option value="due" <?=$mode==='due'?'selected':''?>>Due</option><option value="topic" <?=$mode==='topic'?'selected':''?>>Topic</option></select>
        </div>
        <div class="col6"><label class="muted">Question mode</label>
          <select name="qmode"><option value="typed" <?=$qmode==='typed'?'selected':''?>>Typed</option><option value="mcq" <?=$qmode==='mcq'?'selected':''?>>MCQ</option></select>
        </div>
        <div class="col6"><label class="muted">Direction</label>
          <select name="dir"><option value="de_en" <?=$dir==='de_en'?'selected':''?>>DE→EN</option><option value="en_de" <?=$dir==='en_de'?'selected':''?>>EN→DE</option></select>
        </div>
        <div class="col6"><label class="muted">Topic</label>
          <select name="topic"><option value="">All</option><?php foreach($topics as $t): ?><option value="<?=h($t)?>" <?=($topic===$t)?'selected':''?>><?=h($t)?></option><?php endforeach; ?></select>
        </div>
        <div class="col6"><label class="muted">Anki box (due)</label>
          <select name="box"><option value="">All</option><?php for($b=1;$b<=4;$b++): ?><option value="<?=$b?>" <?=($boxFilter===$b)?'selected':''?>><?=h(boxLabel($b))?></option><?php endfor; ?></select>
        </div>
        <div class="col6"><label class="muted">Questions/session</label><input type="number" name="limit" min="5" max="50" value="<?=h((string)$limit)?>"></div>
        <div class="col12"><button class="btn2" type="submit">Apply</button></div>
      </form>
    </div>
  <?php endif; ?>
<?php }


if($page==='progress'){
  $s = stats($pdo,(int)$user['id']);
  $mastery = topicMastery($pdo,(int)$user['id'],$cards);

  // Series
  $learn60 = learnedSeries($pdo,(int)$user['id'], 60);
  $acc60 = accuracySeries($pdo,(int)$user['id'], 60);

  $cumVals = array_map(fn($r)=> (int)$r['cum'], $learn60);
  $newVals = array_map(fn($r)=> (int)$r['new'], $learn60);
  $accVals = array_map(fn($r)=> ($r['acc']===null?0.0:(float)$r['acc']), $acc60);

  $maxNew = max(1, max($newVals));
  ?>
  <div class="card">
    <h2>Progress</h2>
    <div class="muted">Visual summary of learning progress (last 60 days). For more practice: Study → Topic and Quiz → Due.</div>
    <div class="hr"></div>
    <div class="row">
      <span class="badge">Tracked: <?=h((string)$s['tracked'])?></span>
      <span class="badge">Learned: <?=h((string)$s['learned'])?></span>
      <span class="badge">Due: <?=h((string)$s['due'])?></span>
      <span class="badge">Anki boxes: <?=h(boxLabel(1))?> <?=h((string)$s['b1'])?> · <?=h(boxLabel(2))?> <?=h((string)$s['b2'])?> · <?=h(boxLabel(3))?> <?=h((string)$s['b3'])?> · <?=h(boxLabel(4))?> <?=h((string)$s['b4'])?></span>
    </div>
  </div>

  <div class="card">
    <h3>Cumulative learned (last 60 days)</h3>
    <div class="muted">Counts new cards that became “learned” on each day, and the cumulative total over this window.</div>
    <div class="hr"></div>
    <?= svgLine($cumVals) ?>
  </div>

  <div class="card">
    <h3>New learned per day (last 60 days)</h3>
    <div class="muted">Daily bars (higher = more new learned that day).</div>
    <div class="hr"></div>
    <div style="display:flex;gap:6px;align-items:end;overflow-x:auto;padding-bottom:8px">
      <?php foreach($learn60 as $pt):
        $hgt = (int)round(90 * ($pt['new'] / $maxNew));
      ?>
        <div style="min-width:18px;text-align:center">
          <div title="<?=h($pt['d'])?>: <?=h((string)$pt['new'])?> new learned"
               style="height:<?=h((string)$hgt)?>px;background:rgba(158,193,255,.65);border-radius:6px"></div>
          <div class="mini muted" style="margin-top:4px"><?=h(substr($pt['d'],8,2))?></div>
        </div>
      <?php endforeach; ?>
    </div>
  </div>

  <div class="card">
    <h3>Accuracy trend (last 60 days)</h3>
    <div class="muted">Daily accuracy based on your quiz/review answers. Days with no activity are shown as 0.</div>
    <div class="hr"></div>
    <?= svgLine($accVals) ?>
    <div class="muted mini" style="margin-top:8px">Tip: If accuracy dips, switch to Study mode for that topic and slow down New/day in Settings.</div>
  </div>

  <div class="card">
    <h3>Topic mastery</h3>
    <div class="muted">Learned percentage per topic (based on “learned” flag).</div>
    <div class="hr"></div>
    <?php foreach($mastery as $t=>$m):
      $pct = $m['total']>0 ? round(100*$m['learned']/$m['total']) : 0;
    ?>
      <div style="margin:10px 0">
        <div class="row between">
          <div class="row">
            <span class="pill"><?=h($t)?></span>
            <span class="badge"><?=h((string)$pct)?>%</span>
            <span class="badge">Learned <?=h((string)$m['learned'])?> / <?=h((string)$m['total'])?></span>
            <span class="badge">Due <?=h((string)$m['due'])?></span>
          </div>
          <div class="row">
            <a class="badge" href="?page=study&mode=topic&topic=<?=urlencode($t)?>">Study</a>
            <a class="badge" href="?page=quiz&mode=due&topic=<?=urlencode($t)?>">Quiz due</a>
          </div>
        </div>
        <div class="bar" style="margin-top:8px"><span style="width:<?=h((string)$pct)?>%"></span></div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php
}

footerHtml();
