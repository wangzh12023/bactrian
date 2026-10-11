///|
/// Where a piece of data came from.
///
/// The interpreter attaches a set of sources to every value. A value is
/// *trusted* when every one of its sources is trusted; which sources count as
/// trusted is decided by the policy (see `@policy`).
pub(all) enum Source {
  /// Written by the user, e.g. an explicit confirmation.
  User
  /// A literal written by the planner. The planner only ever sees the user's
  /// request, so a plan literal is as trustworthy as the request itself.
  Plan
  /// Returned by the named tool, or computed from such data.
  Tool(String)
  /// Authored by the named external party (an e-mail sender, the counterparty
  /// of a transaction, the editor of a shared file, ...).
  Party(String)
} derive(Eq, Compare, Hash, Debug, ToJson)

///|
/// Renders a source the way it is shown in traces and explanations.
pub fn Source::render(self : Source) -> String {
  match self {
    User => "user"
    Plan => "plan"
    Tool(name) => "tool:\{name}"
    Party(name) => "party:\{name}"
  }
}

///|
/// Who is allowed to read a piece of data.
///
/// `Public` is the top of the confidentiality order (anyone may read);
/// `Only(set)` restricts readers to the named principals (e-mail addresses,
/// IBANs, user names, ... — whatever identifiers the tools use).
pub(all) enum Readers {
  Public
  Only(@iset.SortedSet[String])
} derive(Eq, Debug)

///|
/// Builds a reader set from a list of principals.
pub fn Readers::only(principals : ArrayView[String]) -> Readers {
  Only(@iset.SortedSet(principals))
}

///|
/// Combining two pieces of data: only principals allowed to read *both* may
/// read the result.
pub fn Readers::meet(self : Readers, other : Readers) -> Readers {
  match (self, other) {
    (Public, r) | (r, Public) => r
    (Only(a), Only(b)) => Only(a.intersection(b))
  }
}

///|
/// `true` when every principal in `principals` may read data with these readers.
pub fn Readers::allows(self : Readers, principals : ArrayView[String]) -> Bool {
  match self {
    Public => true
    Only(set) => principals.iter().all(p => set.contains(p))
  }
}

///|
/// `self` is at most as permissive as `other`: everyone who may read `self`
/// may also read `other`.
pub fn Readers::within(self : Readers, other : Readers) -> Bool {
  match (self, other) {
    (_, Public) => true
    (Public, Only(_)) => false
    (Only(a), Only(b)) => a.subset(b)
  }
}

///|
pub fn Readers::render(self : Readers) -> String {
  match self {
    Public => "public"
    Only(_) => "{" + self.principals().join(", ") + "}"
  }
}

///|
/// The named readers in lexical order (empty for `Public`).
pub fn Readers::principals(self : Readers) -> Array[String] {
  match self {
    Public => []
    Only(set) => {
      let names = set.to_array()
      names.sort_by((a, b) => a.lexical_compare(b))
      names
    }
  }
}

///|
pub impl ToJson for Readers with fn to_json(self) {
  match self {
    Public => "public"
    Only(_) => Json::array(self.principals().map(p => Json::string(p)))
  }
}

///|
/// A security label: the product of an integrity component (`sources`), a
/// confidentiality component (`readers`) and a provenance component
/// (`origins`, the ids of the tool calls whose results flowed into the value).
///
/// `origins` never influences a security decision; it exists so that a denial
/// can be explained as a concrete data-flow path.
pub(all) struct Label {
  sources : @iset.SortedSet[Source]
  readers : Readers
  origins : @iset.SortedSet[Int]
} derive(Eq, Debug)

///|
/// The least element: no sources, readable by anyone, no provenance.
/// `join(bottom(), l) == l` for every label `l`.
pub fn Label::bottom() -> Label {
  {
    sources: @iset.SortedSet::new(),
    readers: Public,
    origins: @iset.SortedSet::new(),
  }
}

///|
/// Label of a literal written in the plan.
pub fn Label::plan() -> Label {
  { ..Label::bottom(), sources: @iset.SortedSet::singleton(Plan), }
}

///|
/// Label of data the user supplied directly.
pub fn Label::user() -> Label {
  { ..Label::bottom(), sources: @iset.SortedSet::singleton(User), }
}

///|
/// Label of data returned by tool `name` in call number `origin`.
pub fn Label::tool(
  name : String,
  readers? : Readers = Public,
  origin? : Int,
) -> Label {
  {
    sources: @iset.SortedSet::singleton(Tool(name)),
    readers,
    origins: match origin {
      Some(id) => @iset.SortedSet::singleton(id)
      None => @iset.SortedSet::new()
    },
  }
}

///|
/// Least upper bound: the result of combining data with labels `self` and
/// `other` carries every source of both and is readable only by principals
/// allowed to read both.
pub fn Label::join(self : Label, other : Label) -> Label {
  {
    sources: self.sources.union(other.sources),
    readers: self.readers.meet(other.readers),
    origins: self.origins.union(other.origins),
  }
}

///|
pub fn Label::join_all(labels : ArrayView[Label]) -> Label {
  labels.iter().fold(init=Label::bottom(), (acc, l) => acc.join(l))
}

///|
/// The partial order of the lattice: `self` may flow into a context labelled
/// `other` without losing information.
pub fn Label::flows_to(self : Label, other : Label) -> Bool {
  self.sources.subset(other.sources) &&
  other.readers.within(self.readers) &&
  self.origins.subset(other.origins)
}

///|
/// Returns a copy with a different reader set.
pub fn Label::with_readers(self : Label, readers : Readers) -> Label {
  { ..self, readers, }
}

///|
/// Returns a copy that additionally records `origin` as provenance.
pub fn Label::with_origin(self : Label, origin : Int) -> Label {
  { ..self, origins: self.origins.add(origin), }
}

///|
/// `true` when every source satisfies `trusted`. A label without sources is
/// trusted (it carries no information from anywhere).
pub fn Label::is_trusted(self : Label, trusted : (Source) -> Bool) -> Bool {
  self.sources.all(s => trusted(s))
}

///|
/// The sources that `trusted` rejects, in a stable order.
pub fn Label::untrusted_sources(
  self : Label,
  trusted : (Source) -> Bool,
) -> Array[Source] {
  self.sources.to_array().filter(s => !trusted(s))
}

///|
/// The default trust rule: only the user and the plan are trusted.
pub fn default_trusted(source : Source) -> Bool {
  source is (User | Plan)
}

///|
/// Compact text form used in traces, e.g. `plan|public` or
/// `tool:read_file|{alice}`.
pub fn Label::render(self : Label) -> String {
  let sources = if self.sources.is_empty() {
    "-"
  } else {
    self.sources.to_array().map(s => s.render()).join("+")
  }
  "\{sources}|\{self.readers.render()}"
}

///|
pub impl ToJson for Label with fn to_json(self) {
  {
    "sources": Json::array(
      self.sources.to_array().map(s => Json::string(s.render())),
    ),
    "readers": self.readers.to_json(),
    "origins": Json::array(
      self.origins.to_array().map(o => Json::number(o.to_double())),
    ),
  }
}
