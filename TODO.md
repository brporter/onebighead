# TODO

* Adjust collection routes so a tenants collection is addressed by name (e.g. /collections/bryanporter.com/) and not numeric tenant ID.
* Get alternative proposals for category tree rendering, and come up with a better idea that a default category of "Uncategorized Items"
* Implement static server-side generated pages for public collections. Private collection views are highly interactive React, experiment with building a front-end that uses static server-side generated pages for public consumption. This might not matter for SEO.
* Make the "Public" / "Private" actually work. Public collections / categories / items are visible anonymously.
* Fix authentication not sticking on the anonymous portions of the site, and fix SPA fallthrough for all cases. Implement unit tests to keep this from happening.