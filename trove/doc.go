// Package trove sends evidence about your Trove object stores to Hallproof:
// how each store is set up, what Trove does to an object when it's written,
// and the bucket records Trove keeps for itself.
//
// # Collectors
//
// trove.stores (population, source object-stores, test storage-encrypted,
// every 15 minutes) has one item per store. Each item names the store, its
// default bucket, the driver behind it and any routed backends. It says
// whether Trove's encrypt middleware runs when objects are written, under
// which scopes, and with which algorithm, and the same for compression and
// scanning. It also carries the store's checksum algorithm, whether CAS is
// on, and which driver capabilities exist (multipart, presign, versioning,
// lifecycle). Everything comes from memory. The collector makes no driver
// call.
//
// Watch multipart_bypasses_middleware. Native multipart uploads go straight
// to the driver and skip Trove's middleware, so on a store where it's true,
// encryption_applied doesn't cover objects written that way.
//
// trove.buckets (population, source object-buckets, no test yet, hourly) lists
// the bucket records in each store's metadata store: name, driver, region,
// versioning, CAS, quotas and lifecycle rules. Stores that share a database
// see the same records, so each record says which stores hold it. Trove only
// writes these records through its own API and dashboard, so an app that
// creates buckets some other way gets an empty list. You only get this
// collector when a metadata store is reachable.
//
// # What is never sent
//
// The adapter never reads a DSN, a URL or an encryption key, and never
// lists objects, so object keys and bodies can't reach Hallproof. Upload
// sessions, CAS entries and a bucket's default_meta stay out too. A custom
// scope goes out as the description you gave it, never its function.
//
// # Scope
//
// Every store is in scope by default. Store settings are the platform's own
// configuration, whatever ends up in the buckets. Bucket records are
// different: by default you only get the ones with no tenant key, the
// buckets the platform made for itself. Set all_tenants (or the witness
// scope's AllTenants) to add your customers' bucket records. They are still
// settings only, marked tenanted, and the tenant key itself isn't sent.
//
// # Options
//
// In a Forge app the options live under extensions.witness.adapters.trove:
//
//	all_tenants: false # add tenant bucket records to trove.buckets
//
// There are no event proofs yet. Trove doesn't record its events to
// Chronicle (see the gaps below).
//
// # With Forge
//
// Blank import the package and mount the witness extension:
//
//	import _ "github.com/hallproof/witness/trove"
//
// The adapter looks in the container for the Trove extension's
// *extension.TroveManager and reads every store it holds, metadata stores
// included. With no manager it falls back to a lone *trove.Trove, read as
// one store called "default". In that single-store mode the extension keeps
// its metadata store out of the container, so trove.buckets is skipped.
//
// # Without Forge
//
//	a := trove.New(store, trove.WithMetadataStore(meta))
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// Use trove.NewManager(m) when you run several stores through a
// TroveManager.
//
// # Dependencies
//
// This module depends on github.com/xraph/trove/extension as well as the
// root trove module. The store manager, the metadata store and its bucket
// records only exist there, so the adapter can't find or read them without
// it. A Forge app running the Trove extension already has it. A plain Go
// app pays for the extension's dependency graph.
//
// # Library gaps
//
// These need changes in Trove, and the adapter reports "unknown" or leaves
// the field out until they land.
//
//   - Backend encryption, public access and retention can't be read. No
//     driver reports S3 SSE, GCS CMEK, a public access block, object lock
//     or bucket lifecycle, so backend_encryption is always "unknown" and
//     storage-encrypted has to rest on cloud evidence for now. A driver
//     capability such as InspectBucket, implemented in s3driver with
//     bucket-scoped calls, would close it.
//   - The extension's enable_encryption setting does nothing; it never
//     registers the encrypt middleware. The adapter reports what's
//     registered, never what's configured.
//   - Native multipart skips middleware, as above.
//   - Trove's Chronicle hook has no caller, so no bucket events are
//     recorded. Its object events also put object keys in resource_id, which
//     must change before they share a stream with any event proof.
//   - The coverage check is unexported in Trove's dashboard code, so this
//     package keeps its own copy. An exported Resolver.Coverage in root
//     Trove would stop the two drifting apart.
//   - In single-store mode the metadata store isn't in the container.
//   - The driver-level bucket listing needs account-wide permission on S3,
//     so the adapter reads only each store's default bucket.
package trove
