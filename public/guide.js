(function () {
  function guideOpen() {
    var m = document.getElementById('guide-modal');
    m.style.display = 'flex';
  }
  function guideClose() {
    var m = document.getElementById('guide-modal');
    m.style.display = 'none';
  }

  document.getElementById('guide-btn').addEventListener('click', function (e) {
    e.stopPropagation();
    guideOpen();
  }, true);

  document.getElementById('guide-close').addEventListener('click', function (e) {
    e.stopPropagation();
    guideClose();
  }, true);

  document.getElementById('guide-ok').addEventListener('click', function (e) {
    e.stopPropagation();
    guideClose();
  }, true);

  document.getElementById('guide-modal').addEventListener('click', function (e) {
    if (e.target === this) guideClose();
  }, true);

  var btn  = document.getElementById('guide-btn');
  var pink = getComputedStyle(document.documentElement).getPropertyValue('--pink').trim() || '#ff0a6c';
  var bg   = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()   || '#080b0f';
  btn.addEventListener('mouseenter', function () {
    this.style.background = pink;
    this.style.color = bg;
  });
  btn.addEventListener('mouseleave', function () {
    this.style.background = 'transparent';
    this.style.color = pink;
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') guideClose();
  });
})();
