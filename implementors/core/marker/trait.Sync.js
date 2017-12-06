(function() {var implementors = {};
implementors["futures"] = ["impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"futures/stream/struct.FuturesUnordered.html\" title=\"struct futures::stream::FuturesUnordered\">FuturesUnordered</a>&lt;T&gt;","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"futures/task/struct.AtomicTask.html\" title=\"struct futures::task::AtomicTask\">AtomicTask</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"futures/executor/struct.NotifyHandle.html\" title=\"struct futures::executor::NotifyHandle\">NotifyHandle</a>",];
implementors["lazycell"] = ["impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"lazycell/struct.AtomicLazyCell.html\" title=\"struct lazycell::AtomicLazyCell\">AtomicLazyCell</a>&lt;T&gt;",];
implementors["mio"] = ["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"mio/struct.Registration.html\" title=\"struct mio::Registration\">Registration</a>","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"mio/struct.SetReadiness.html\" title=\"struct mio::SetReadiness\">SetReadiness</a>",];
implementors["scoped_tls"] = ["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"scoped_tls/struct.ScopedKey.html\" title=\"struct scoped_tls::ScopedKey\">ScopedKey</a>&lt;T&gt;",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
