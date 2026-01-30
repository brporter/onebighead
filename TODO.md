# TODO

* On first sign-in, have a welcome experience that asks users to name their tenant and walk them through setting up their first collection. It should be skippable so they can just get started quickly - in which case their tenant name is just their email address.
* Adjust collection routes so a tenants collection is addressed by name (e.g. /collections/bryanporter.com/) and not numeric tenant ID.
* Fix settings view stylings - it's terrible.
* Get alternative proposals for category tree rendering, and come up with a better idea that a default category of "Uncategorized Items"
* Implement "I have" vs. "I want" tags
* Implement a generic tag system and build the "I have" and "I want" mechanism on top of that
* Implement static server-side generated pages for public collections. Private collection views are highly interactive React, experiment with building a front-end that uses static server-side generated pages for public consumption. This might not matter for SEO.
* Make the "Public" / "Private" actually work. Public collections / categories / items are visible anonymously.
* Fix authentication not sticking on the anonymous portions of the site, and fix SPA fallthrough for all cases. Implement unit tests to keep this from happening.