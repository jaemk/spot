begin;
alter table spot.tracks
    drop column artist_ids,
    drop column album_name,
    drop column album_id,
    drop column album_images;
commit;