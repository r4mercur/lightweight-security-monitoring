package repository

import (
	"slices"
	"sort"
	"time"
)

// entry is one stored item. It is referenced from the insertion-order list
// and from the per-key index; removed entries are flagged and skipped until
// the insertion-order list is compacted.
type entry[T any] struct {
	ts      time.Time
	key     string
	val     T
	removed bool
}

// indexedLog stores items in insertion order and additionally indexes them
// by key (the source IP), sorted by timestamp. It is not safe for concurrent
// use; MemoryStore guards it with a lock.
//
//	add          O(log k) – k = items of that key; out-of-order items are inserted in place
//	since/count  O(log k + result)
//	capacity     oldest inserted item is evicted first
//	retention    items with a timestamp before the cutoff are removed
type indexedLog[T any] struct {
	order    []*entry[T] // insertion order; order[head:] is live or removed
	head     int
	byKey    map[string][]*entry[T]
	live     int
	capacity int // 0 = unlimited
}

func newIndexedLog[T any](capacity int) *indexedLog[T] {
	return &indexedLog[T]{byKey: make(map[string][]*entry[T]), capacity: capacity}
}

// add stores v and returns how many items were evicted to stay within capacity.
func (l *indexedLog[T]) add(key string, ts time.Time, v T) (evicted int) {
	e := &entry[T]{ts: ts, key: key, val: v}
	l.order = append(l.order, e)

	s := l.byKey[key]
	// Insert after all items with ts <= e.ts; for in-order data this is an append.
	i := sort.Search(len(s), func(i int) bool { return s[i].ts.After(ts) })
	l.byKey[key] = slices.Insert(s, i, e)
	l.live++

	for l.capacity > 0 && l.live > l.capacity {
		l.evictOldest()
		evicted++
	}
	l.compact()
	return evicted
}

func (l *indexedLog[T]) evictOldest() {
	for l.head < len(l.order) {
		e := l.order[l.head]
		l.order[l.head] = nil
		l.head++
		if !e.removed {
			l.removeFromIndex(e)
			e.removed = true
			l.live--
			return
		}
	}
}

func (l *indexedLog[T]) removeFromIndex(e *entry[T]) {
	s := l.byKey[e.key]
	i := sort.Search(len(s), func(i int) bool { return !s[i].ts.Before(e.ts) })
	for ; i < len(s); i++ {
		if s[i] == e {
			s = slices.Delete(s, i, i+1)
			break
		}
	}
	if len(s) == 0 {
		delete(l.byKey, e.key)
	} else {
		l.byKey[e.key] = s
	}
}

// pruneBefore removes all items with a timestamp before cutoff.
func (l *indexedLog[T]) pruneBefore(cutoff time.Time) (removed int) {
	for key, s := range l.byKey {
		n := sort.Search(len(s), func(i int) bool { return !s[i].ts.Before(cutoff) })
		if n == 0 {
			continue
		}
		for _, e := range s[:n] {
			e.removed = true
		}
		if n == len(s) {
			delete(l.byKey, key)
		} else {
			// Copy instead of reslicing so the pruned entries can be garbage collected.
			l.byKey[key] = slices.Clone(s[n:])
		}
		removed += n
	}
	l.live -= removed
	l.compact()
	return removed
}

// compact drops removed entries from the insertion-order list once they make
// up more than half of it, so memory stays proportional to live items.
func (l *indexedLog[T]) compact() {
	dead := len(l.order) - l.head - l.live
	if l.head < 1024 && dead < 1024 {
		return
	}
	if l.head+dead <= len(l.order)/2 {
		return
	}
	order := make([]*entry[T], 0, l.live+l.live/4)
	for _, e := range l.order[l.head:] {
		if e != nil && !e.removed {
			order = append(order, e)
		}
	}
	l.order, l.head = order, 0
}

// update calls fn on the stored items of key, newest first, until fn returns
// true. It reports whether fn returned true for an item.
func (l *indexedLog[T]) update(key string, fn func(*T) bool) bool {
	s := l.byKey[key]
	for _, v := range slices.Backward(s) {
		if fn(&v.val) {
			return true
		}
	}
	return false
}

// since returns the items of key with a timestamp after t, oldest first.
func (l *indexedLog[T]) since(key string, t time.Time) []T {
	s := l.byKey[key]
	i := sort.Search(len(s), func(i int) bool { return s[i].ts.After(t) })
	out := make([]T, 0, len(s)-i)
	for _, e := range s[i:] {
		out = append(out, e.val)
	}
	return out
}

// newest returns up to limit items, newest first, plus the number of items
// that match. With a key, items are ordered by timestamp; without, by insertion.
// A non-nil match filters the items; counting them then scans all candidates.
func (l *indexedLog[T]) newest(key string, limit int, match func(T) bool) (items []T, total int) {
	visit := func(v T) bool { // reports whether to continue
		if match != nil && !match(v) {
			return true
		}
		total++
		if len(items) < limit {
			items = append(items, v)
		}
		return match != nil || len(items) < limit
	}

	if key != "" {
		s := l.byKey[key]
		for _, v := range slices.Backward(s) {
			if !visit(v.val) {
				break
			}
		}
		if match == nil {
			total = len(s)
		}
		return items, total
	}
	for i := len(l.order) - 1; i >= l.head; i-- {
		if e := l.order[i]; e != nil && !e.removed && !visit(e.val) {
			break
		}
	}
	if match == nil {
		total = l.live
	}
	return items, total
}

// eachSince calls fn for every item with a timestamp after t, in no particular order.
func (l *indexedLog[T]) eachSince(t time.Time, fn func(T)) {
	for _, s := range l.byKey {
		i := sort.Search(len(s), func(i int) bool { return s[i].ts.After(t) })
		for _, e := range s[i:] {
			fn(e.val)
		}
	}
}

func (l *indexedLog[T]) len() int  { return l.live }
func (l *indexedLog[T]) keys() int { return len(l.byKey) }
