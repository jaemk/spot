begin;
alter table spot.tracks
    alter column raw drop not null,
    add column artist_ids text[],
    add column album_name text,
    add column album_id text,
    add column album_images jsonb;

update spot.tracks
    set album_name = coalesce(raw->'item'->'album'->>'name', raw->'track'->'album'->>'name')
    where album_name is null;

update spot.tracks
    set album_id = coalesce(raw->'item'->'album'->>'id', raw->'track'->'album'->>'id')
    where album_id is null;

update spot.tracks
    set album_images = coalesce(raw->'item'->'album'->'images', raw->'track'->'album'->'images')
    where album_images is null;

update spot.tracks
    set artist_ids = (
        select array_agg(artists.id)
        from jsonb_to_recordset(raw->'item'->'artists') as artists(id text)
    )
    where artist_ids is null
        and raw->'item' is not null;

update spot.tracks
    set artist_ids = (
        select array_agg(artists.id)
        from jsonb_to_recordset(raw->'track'->'artists') as artists(id text)
    )
    where artist_ids is null
      and raw->'track' is not null;

alter table spot.tracks
    alter column artist_ids set not null,
    alter column album_name set not null,
    alter column album_id set not null,
    alter column album_images set not null;
commit;