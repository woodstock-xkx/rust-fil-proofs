use cpu_time::ProcessTime;
use filecoin_proofs::constants::{LIVE_SECTOR_SIZE, POST_SECTORS_COUNT};
use filecoin_proofs::fr32::write_padded;
use filecoin_proofs::pieces::get_aligned_source;
use filecoin_proofs::{
    generate_post, seal, Commitment, PaddedBytesAmount, PoRepConfig, PoRepProofPartitions,
    PoStConfig, PoStProofPartitions, SectorSize, UnpaddedBytesAmount,
};
use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

fn add_piece<R, W>(
    mut source: &mut R,
    target: &mut W,
    piece_size: UnpaddedBytesAmount,
    piece_lengths: &[UnpaddedBytesAmount],
) -> std::io::Result<usize>
where
    R: Read + ?Sized,
    W: Read + Write + Seek + ?Sized,
{
    let (_, mut aligned_source) = get_aligned_source(&mut source, &piece_lengths, piece_size);
    write_padded(&mut aligned_source, target)
}

struct FuncMeasurement<T> {
    cpu_time: Duration,
    wall_time: Duration,
    return_value: T,
}

fn measure<T, F: FnOnce() -> Result<T, failure::Error>>(
    f: F,
) -> Result<FuncMeasurement<T>, failure::Error> {
    let cpu_time_start = ProcessTime::now();
    let wall_start_time = Instant::now();

    let x = f()?;

    Ok(FuncMeasurement {
        cpu_time: cpu_time_start.elapsed(),
        wall_time: wall_start_time.elapsed(),
        return_value: x,
    })
}

fn main() {
    pretty_env_logger::init_timed();

    let args: Vec<String> = env::args().collect();

    //    let num_sectors_to_seal = args[1].parse::<usize>().unwrap();
    let num_sectors_to_seal = 1;
    let control = args[2].parse::<usize>().unwrap();

    let x: Result<(), failure::Error> = Ok(()).and_then(|_| {
        let sector_size = LIVE_SECTOR_SIZE;

        let number_of_bytes_in_piece =
            UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size.clone()));

        let mut ss: Vec<String> = Default::default();
        let mut rs: Vec<String> = Default::default();
        let mut qs: Vec<String> = Default::default();

        for n in 0..num_sectors_to_seal {
            std::fs::create_dir_all("/var/tmp/laser")?;

            let s = format!(
                "/var/tmp/laser/staged-sector-psc{}-ss{}-n{}",
                POST_SECTORS_COUNT, sector_size, n
            );

            let r = format!(
                "/var/tmp/laser/sealed-sector-psc{}-ss{}-n{}",
                POST_SECTORS_COUNT, sector_size, n
            );

            let q = format!(
                "/var/tmp/laser/sealed-sector-psc{}-ss{}-n{}-commr",
                POST_SECTORS_COUNT, sector_size, n
            );

            qs.push(q);
            rs.push(r);
            ss.push(s.clone());
        }

        if control == 0 {
            for n in 0..num_sectors_to_seal {
                let p = format!(
                    "/var/tmp/laser/piece-psc{}-ss{}-n{}",
                    POST_SECTORS_COUNT, sector_size, n
                );

                println!("generating sector {}", n);

                let bs: Vec<u8> = (0..number_of_bytes_in_piece.0)
                    .map(|_| rand::random::<u8>())
                    .collect();

                // create piece file and write bytes
                let mut f1 = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .read(true)
                    .open(&p)
                    .expect("failed to create/open f1");

                f1.write_all(&bs).expect("failed to write to f1");

                // seek cursor back to beginning
                f1.seek(SeekFrom::Start(0)).expect("failed to seek f1");

                // create staged sector
                let mut f2 = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .read(true)
                    .truncate(true)
                    .open(ss[n].clone())
                    .expect("failed to create/open f2");

                // seek cursor back to beginning
                f2.seek(SeekFrom::Start(0)).expect("failed to seek f2");

                add_piece(&mut f1, &mut f2, number_of_bytes_in_piece, &[])
                    .expect("failed to add piece");

                let output = seal(
                    PoRepConfig(SectorSize(sector_size.clone()), PoRepProofPartitions(2)),
                    &ss[n],
                    &rs[n],
                    &[0; 31],
                    &[0; 31],
                    &[number_of_bytes_in_piece],
                )
                .expect("failed to seal");

                // create piece file and write bytes
                let mut fq = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .read(true)
                    .open(&qs[n])
                    .expect("failed to create/open fq");

                fq.write_all(&output.comm_r).expect("failed to write to fq");

                // seek cursor back to beginning
                fq.seek(SeekFrom::Start(0)).expect("failed to seek fq");
            }
        }

        if control == 1 {
            let mut xs: Vec<(Option<String>, Commitment)> = Default::default();

            for n in 0..num_sectors_to_seal {
                let mut xq = OpenOptions::new()
                    .read(true)
                    .open(&qs[n])
                    .expect("failed to create/open fq");

                let mut buffer: [u8; 32] = [0; 32];

                xq.read(&mut buffer)?;

                xs[n] = (Some(rs[n].clone()), buffer);
            }

            println!("generating PoSt {:?} {}", xs, POST_SECTORS_COUNT);

            let FuncMeasurement {
                cpu_time: t1,
                wall_time: t2,
                return_value: x,
            } = measure(|| {
                generate_post(
                    PoStConfig(SectorSize(sector_size.clone()), PoStProofPartitions(1)),
                    [0u8; 32],
                    xs,
                )
            })
            .expect("failed to generate PoSt");

            println!("cpu_time: {}s, wall_time: {}s", t1.as_secs(), t2.as_secs());

            assert!(x.proofs.len() > 0);
        }

        Ok(())
    });

    x.expect("test failed");
}
