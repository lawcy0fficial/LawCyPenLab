/* LawCypenLab :: AEGIS STATION — Next-Generation Animation Engine v25
   Starfield · Scan lines · Live clock · Table stagger · Toasts · Typed text */
(function(){"use strict";

var rm=window.matchMedia&&window.matchMedia("(prefers-reduced-motion:reduce)").matches;

/* ── Starfield ─────────────────────────────────────────────────────── */
function initStarfield(){
  var c=document.getElementById("starfield");
  if(!c)return;
  var x=c.getContext("2d"),stars=[],shooters=[],w,h,dpr,frame=0;

  var COLORS=["rgba(255,255,255,",    /* white */
              "rgba(100,210,255,",    /* cyan tint */
              "rgba(200,180,255,",    /* purple tint */
              "rgba(255,220,180,"];   /* warm tint */

  function resize(){
    dpr=Math.min(window.devicePixelRatio||1,2);
    w=window.innerWidth;h=window.innerHeight;
    c.width=w*dpr;c.height=h*dpr;
    c.style.width=w+"px";c.style.height=h+"px";
    x.setTransform(dpr,0,0,dpr,0,0);
    var n=Math.round((w*h)/7500);stars=[];
    for(var i=0;i<n;i++){
      var col=COLORS[Math.floor(Math.random()*COLORS.length)];
      stars.push({
        x:Math.random()*w,y:Math.random()*h,
        r:Math.random()*1.4+0.2,
        a:Math.random()*0.55+0.1,
        ph:Math.random()*Math.PI*2,
        sp:Math.random()*0.18+0.03,
        col:col
      });
    }
  }

  function spawnShooter(){
    if(rm)return;
    shooters.push({
      x:Math.random()*w*0.6,y:Math.random()*h*0.4,
      len:Math.random()*120+60,
      sp:Math.random()*6+4,
      a:Math.PI/4+Math.random()*0.3-0.15,
      life:1,decay:0.025+Math.random()*0.02
    });
  }

  function draw(t){
    x.clearRect(0,0,w,h);
    /* stars */
    for(var i=0;i<stars.length;i++){
      var s=stars[i];
      var tw=rm?0:Math.sin(t*0.001*s.sp+s.ph)*0.35;
      var al=Math.max(0,Math.min(1,s.a+tw));
      x.beginPath();x.arc(s.x,s.y,s.r,0,Math.PI*2);
      x.fillStyle=s.col+al.toFixed(3)+")";
      x.fill();
    }
    /* shooting stars */
    for(var j=shooters.length-1;j>=0;j--){
      var sh=shooters[j];
      x.save();
      x.translate(sh.x,sh.y);x.rotate(sh.a);
      var grad=x.createLinearGradient(0,0,sh.len,0);
      grad.addColorStop(0,"rgba(0,212,255,0)");
      grad.addColorStop(0.3,"rgba(0,212,255,"+sh.life.toFixed(2)+")");
      grad.addColorStop(1,"rgba(255,255,255,0)");
      x.strokeStyle=grad;x.lineWidth=1.5;
      x.beginPath();x.moveTo(0,0);x.lineTo(sh.len,0);x.stroke();
      x.restore();
      sh.x+=Math.cos(sh.a)*sh.sp;sh.y+=Math.sin(sh.a)*sh.sp;sh.life-=sh.decay;
      if(sh.life<=0)shooters.splice(j,1);
    }
    /* occasional shooting star */
    frame++;
    if(!rm&&frame%220===0&&Math.random()>0.4)spawnShooter();
    if(!rm)requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener("resize",resize);
  if(rm){draw(0);}else{requestAnimationFrame(draw);}
}

/* ── Progress Bar ───────────────────────────────────────────────────── */
function initProgress(){
  var bar=document.getElementById("page-progress");if(!bar)return;
  function start(){
    bar.classList.add("active");bar.style.width="18%";
    setTimeout(function(){bar.style.width="52%";},90);
    setTimeout(function(){bar.style.width="76%";},280);
  }
  document.addEventListener("click",function(e){
    var a=e.target.closest&&e.target.closest("a[href]");
    if(!a)return;
    var h=a.getAttribute("href")||"";
    if(h.startsWith("#")||h.startsWith("javascript:")||a.target==="_blank")return;
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;
    start();
  });
  document.addEventListener("submit",function(){start();});
  window.addEventListener("pageshow",function(){
    bar.style.width="100%";
    setTimeout(function(){bar.classList.remove("active");setTimeout(function(){bar.style.width="0%";},300);},160);
  });
}

/* ── Live UTC Clock ─────────────────────────────────────────────────── */
function initClock(){
  var el=document.getElementById("live-clock");if(!el)return;
  function tick(){
    var d=new Date();
    el.textContent=d.toISOString().slice(0,19).replace("T"," ")+" UTC";
  }
  tick();setInterval(tick,1000);
}

/* ── Panel scan lines (inject scanline div into each .panel) ─────────── */
function initScanlines(){
  if(rm)return;
  var panels=document.querySelectorAll(".panel");
  panels.forEach(function(p,i){
    var sl=document.createElement("div");
    sl.className="panel-scanline";
    sl.style.animationDelay=(i*0.9)+"s";
    p.appendChild(sl);
  });
}

/* ── Table row stagger ──────────────────────────────────────────────── */
function initTableStagger(){
  if(rm)return;
  var rows=document.querySelectorAll(".data-table tbody tr, .data-table tr");
  rows.forEach(function(r,i){
    r.style.animationDelay=(i*0.045)+"s";
  });
}

/* ── Typewriter effect for .typewriter elements ─────────────────────── */
function initTypewriter(){
  if(rm)return;
  var els=document.querySelectorAll(".typewriter");
  els.forEach(function(el){
    var text=el.textContent;
    el.textContent="";el.style.borderRight="2px solid var(--cyan)";
    var i=0;
    var iv=setInterval(function(){
      el.textContent+=text[i++];
      if(i>=text.length){
        clearInterval(iv);
        setTimeout(function(){el.style.borderRight="none";},800);
      }
    },38);
  });
}

/* ── Command Palette ────────────────────────────────────────────────── */
function initCommandPalette(){
  var links=Array.prototype.slice.call(document.querySelectorAll("nav.navlist a[href]"));
  if(!links.length)return;
  var entries=links.map(function(a){
    var group="";
    var node=a;
    while(node){node=node.previousElementSibling;
      if(node&&node.classList&&node.classList.contains("navlabel")){group=node.textContent.trim();break;}
    }
    return{label:a.textContent.replace(/^[◆\s]+/,"").trim(),href:a.getAttribute("href"),group:group};
  });

  var overlay=document.createElement("div");overlay.id="cmdk-overlay";
  overlay.innerHTML='<div id="cmdk-box" role="dialog" aria-modal="true">'+
    '<input id="cmdk-input" type="text" placeholder="⌘ Jump to any page…" autocomplete="off">'+
    '<div id="cmdk-list"></div></div>';
  document.body.appendChild(overlay);

  var inp=overlay.querySelector("#cmdk-input"),list=overlay.querySelector("#cmdk-list");
  var sel=0,filt=entries;

  function render(){
    list.innerHTML="";
    if(!filt.length){list.innerHTML='<div class="cmdk-empty">No matching pages.</div>';return;}
    filt.forEach(function(item,i){
      var el=document.createElement("div");el.className="cmdk-item"+(i===sel?" sel":"");
      el.innerHTML="<span>"+item.label+"</span><span class='grp'>"+item.group+"</span>";
      el.addEventListener("mouseenter",function(){sel=i;render();});
      el.addEventListener("click",function(){nav(item);});
      list.appendChild(el);
    });
    var s=list.querySelector(".sel");if(s)s.scrollIntoView({block:"nearest"});
  }
  function nav(item){close();window.location.href=item.href;}
  function filter(){
    var q=inp.value.trim().toLowerCase();
    filt=!q?entries:entries.filter(function(e){
      return e.label.toLowerCase().includes(q)||e.group.toLowerCase().includes(q);
    });sel=0;render();
  }
  function open(){overlay.classList.add("open");inp.value="";filter();setTimeout(function(){inp.focus();},10);}
  function close(){overlay.classList.remove("open");}

  inp.addEventListener("input",filter);
  inp.addEventListener("keydown",function(e){
    if(e.key==="ArrowDown"){e.preventDefault();sel=Math.min(sel+1,filt.length-1);render();}
    else if(e.key==="ArrowUp"){e.preventDefault();sel=Math.max(sel-1,0);render();}
    else if(e.key==="Enter"){e.preventDefault();if(filt[sel])nav(filt[sel]);}
    else if(e.key==="Escape")close();
  });
  overlay.addEventListener("click",function(e){if(e.target===overlay)close();});
  document.addEventListener("keydown",function(e){
    if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k"){e.preventDefault();open();}
  });
  document.querySelectorAll(".kbd-hint[data-cmdk]").forEach(function(h){h.addEventListener("click",open);});
}

/* ── Toast Notification System ──────────────────────────────────────── */
window.AEGIS={};
window.AEGIS.toast=function(msg,type,dur){
  var c=document.getElementById("toast-container");
  if(!c){c=document.createElement("div");c.id="toast-container";document.body.appendChild(c);}
  var t=document.createElement("div");t.className="toast";
  t.style.borderLeftColor=type==="danger"?"var(--danger)":type==="warn"?"var(--amber)":type==="success"?"var(--success)":"var(--cyan)";
  t.textContent=msg;c.appendChild(t);
  setTimeout(function(){t.classList.add("fade-out");setTimeout(function(){t.remove();},300);},(dur||3000));
};

/* ── Mobile sidebar toggle ──────────────────────────────────────────── */
function initMobileNav(){
  var toggle=document.getElementById("menu-toggle");
  var sidebar=document.querySelector(".sidebar");
  var backdrop=document.getElementById("sidebar-backdrop");
  if(!toggle||!sidebar)return;

  function setOpen(open){
    sidebar.classList.toggle("open",open);
    toggle.setAttribute("aria-expanded",open?"true":"false");
    if(backdrop)backdrop.classList.toggle("open",open);
    document.body.style.overflow=open?"hidden":"";
  }

  toggle.addEventListener("click",function(){
    setOpen(!sidebar.classList.contains("open"));
  });
  document.addEventListener("click",function(e){
    if(sidebar.classList.contains("open")&&!sidebar.contains(e.target)&&!toggle.contains(e.target)){
      setOpen(false);
    }
  });
  document.addEventListener("keydown",function(e){
    if(e.key==="Escape"&&sidebar.classList.contains("open"))setOpen(false);
  });
  // close the drawer automatically after navigating (link click) on mobile
  sidebar.addEventListener("click",function(e){
    if(e.target.closest("a"))setOpen(false);
  });
}

/* ── Page-level glow on active nav item ─────────────────────────────── */
function initNavGlow(){
  var active=document.querySelector(".navlist a.active");
  if(!active)return;
  active.scrollIntoView({block:"nearest",behavior:"smooth"});
}

/* ── Badge entrance animation ───────────────────────────────────────── */
function initBadges(){
  if(rm)return;
  var badges=document.querySelectorAll(".badge");
  badges.forEach(function(b,i){
    b.style.animationDelay=(i*0.06)+"s";
  });
}

/* ── Init all ───────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded",function(){
  initStarfield();
  initProgress();
  initClock();
  initScanlines();
  initTableStagger();
  initTypewriter();
  initCommandPalette();
  initMobileNav();
  initNavGlow();
  initBadges();
});
})();
